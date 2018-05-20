#define FUSE_USE_VERSION 26
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fuse.h>
#include <sys/mman.h>
#define MAX_FILENAME_LENGTH 255
#define META_BLOCK_START 1

typedef unsigned long long big_int;
#define mem_size (4 * 1024 * 1024 * (size_t)1024)
#define BLOCK_SIZE (4 * 1024)
#define BLOCK_DATA_SIZE (BLOCK_SIZE - sizeof(big_int))
#define BLOCK_NUM (mem_size / BLOCK_SIZE)

#define ROOTBLOCK_START 0
#define ROOTBLOCK_INODE 1
#define STATBLOCK_START 2
#define METABLOCK_START 3
#define METABLOCK_NUM (BLOCK_NUM / 8 /BLOCK_SIZE)
#define GROUP_NUM (BLOCK_NUM / 64)
#define GROUP_NUM_PER_BLOCK (BLOCK_SIZE / sizeof(big_int))

struct content_t {
    big_int head;
    big_int tail;
};

struct inode {
    struct content_t content;
    big_int self_block_id;
    struct stat st;
};

struct filenode {
    char filename[MAX_FILENAME_LENGTH+1];

    int dir;
    struct filenode * child;
    struct filenode * parent;
    struct filenode * next;
    struct filenode * prev; //space for time

    struct inode * link; 

    big_int self_block_id;
};

struct stat_block {
    big_int block_num;
    big_int block_used;
};

struct block {
    big_int next;
    unsigned char data[BLOCK_DATA_SIZE];
};

static struct stat get_default_stat(int is_dir) {
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if (is_dir)
        st.st_mode = S_IFDIR | 0755;
    else
        st.st_mode = S_IFREG | 0755;
    st.st_uid = fuse_get_context()->uid;
    st.st_gid = fuse_get_context()->gid;
    st.st_nlink = 1;
    st.st_size = 0;
    st.st_blksize = BLOCK_DATA_SIZE;
    st.st_blocks = 0;
    return st;
}

void * blocks[BLOCK_NUM];


void * new_block() {
    void * ret;
  ret = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(ret, 0, BLOCK_SIZE);
  return ret;
}

//64 bits in 1 group (big_int)
void set_block_bit(big_int block_id, int bit) {
    big_int group_id = block_id / 64;

    big_int _op=0;
    if (bit) {
        
        _op = 1ULL << block_id % 64;
       ((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK] |= _op;
    }
    else {
        _op = ~(1ULL << block_id % 64);
        ((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK] &= _op;
    }
}

big_int get_group_bits(big_int group_id) {
    return ((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK];
}

big_int search_for_free_block() {
    big_int block_id;
    big_int group_id;
    big_int group_bits;

    //printf("serching for free block......\n");
    for (group_id = 0; ((group_bits = get_group_bits(group_id)) == 0xffffffffffffffff) && (group_id < GROUP_NUM); group_id++);
    //printf("get group not full id:%llu, group bits=%llx\n",group_id,group_bits);
    if (group_id >= GROUP_NUM) return -1;

    block_id = group_id * 64;
    while (group_bits % 2) {
        block_id++;
        group_bits >>= 1;
    }
    //printf("final block id:%llu\n",block_id);
    return block_id;
}

big_int allocate_block() {
    big_int block_id = search_for_free_block();
    if (block_id==-1) return -1;
    blocks[block_id] = new_block();
    set_block_bit(block_id,1);

    ((struct stat_block*)(blocks[STATBLOCK_START]))->block_used++;
    return block_id;
}

void free_block(big_int block_id) {
    munmap(blocks[block_id], BLOCK_SIZE);
    set_block_bit(block_id,0);
    ((struct stat_block*)(blocks[STATBLOCK_START]))->block_used--;
}

//create one if no next
big_int get_next_block(struct inode *node, big_int p) {
    if (p>BLOCK_NUM) return -1;
    struct block * p_b = (struct block *)blocks[p];
    if (!p_b) return -1;
    if (!p_b->next) {
        big_int q = allocate_block();
        p_b->next = q;
        node->content.tail = q;
        return q;
    }
    else return p_b->next;
}

big_int locate(struct inode * node, off_t offset) {
    big_int p = node->content.head;
    if (p == 0) {
        p = allocate_block();
        node->content.head = p;
        node->content.tail = p;
    }

    big_int logical_block_id = offset / BLOCK_DATA_SIZE;
    big_int real_max_block_id = node->st.st_size / BLOCK_DATA_SIZE;

    //location in section
    if (logical_block_id <= real_max_block_id) {
        for (int i = BLOCK_DATA_SIZE; i<offset && p!=node->content.tail; i+=BLOCK_DATA_SIZE)
            p = ((struct block *)blocks[p])->next;
        return p;
    }

    //location out of section
    p = node->content.tail;
    struct block * p_b;
    for (int i = ((node->st.st_size+BLOCK_DATA_SIZE-1)/BLOCK_DATA_SIZE)*BLOCK_DATA_SIZE;i<offset;i+=BLOCK_DATA_SIZE)
        p = get_next_block(node,p);
    return p;
}

struct filenode *get_parent_dir_by_path(struct filenode * parent,const char *path) {
    //printf("getting parent dir by path:%s\n",path);
    if (!parent) parent = (struct filenode *)blocks[ROOTBLOCK_START];
    char name[MAX_FILENAME_LENGTH];
    memset(name,0,sizeof(name));
    char * pos = strchr(path,'/');
    if (pos == NULL)
        return parent;
    else
        memcpy(name , path , (pos-path)*sizeof(char));

    struct filenode * child = parent->child;
    while (child) {
        if (child->dir && strcmp(name,child->filename)==0)
            return get_parent_dir_by_path(child , pos + 1);
        child = child->next;
    }
    return parent;
}

struct filenode *get_filenode_by_path(const char *path)
{
    //printf("getting file node by path:%s\n",path);
    if (path[0]==0) return (struct filenode *)blocks[ROOTBLOCK_START];
    struct filenode * parent = get_parent_dir_by_path(NULL, path);
    struct filenode *node = parent->child;

    char * name = path, * pos;
    while (pos = strchr(name,'/'))
        name = pos + 1;

    while(node) {
        if(strcmp(node->filename, name) != 0)
            node = node->next;
        else {
            return node;
        }
    }
    return NULL;
}

struct filenode * create_filenode(const char *path, struct inode * org, int is_dir)
{
    printf("start create filenode...\n");
    big_int block_id_for_filenode = allocate_block();
    big_int block_id_for_inode;
    struct inode * in;
    if (block_id_for_filenode == -1) {
        //printf("no more space?kidding?\n");
        return NULL;   //no more space
    }

    if (!org) {
        block_id_for_inode = allocate_block();
        if (block_id_for_inode == -1) {
            free_block(block_id_for_filenode);
            return NULL;
        }
        in = (struct inode *)blocks[block_id_for_inode];
        in->st = get_default_stat(is_dir);
        in->content.head = 0;
        in->content.tail = 0;
        in->self_block_id = block_id_for_inode;
    }

    char * name = path, * pos;
    while (pos = strchr(name,'/'))
        name = pos + 1;

    struct filenode *new = (struct filenode *)blocks[block_id_for_filenode];
    new->parent = get_parent_dir_by_path(NULL , path);

    strncpy(new->filename, name, MAX_FILENAME_LENGTH + 1);
    new->dir = is_dir;
    new->self_block_id = block_id_for_filenode;
    new->child = NULL;
    new->next = new->parent->child;
    new->prev = NULL;
    if (new->next)
        new->next->prev = new;
    new->parent->child = new;
    if (!org)
        new->link = in;
    else
        new->link = org;

    printf("end creating file node...\n");
    return new;
}

void *oshfs_init()
{
    //allocate root pointer
    blocks[ROOTBLOCK_START] = new_block();
    blocks[ROOTBLOCK_INODE] = new_block();
    struct filenode *root = (struct filenode *)blocks[ROOTBLOCK_START];
    struct inode *in = (struct inode *)blocks[ROOTBLOCK_INODE];
    root->filename[0]='/'; root->filename[1]='\0';
    root->child = NULL;
    root->next = NULL;
    root->prev = NULL;
    root->parent = NULL;
    root->dir = 1;
    root->link = in;
    in->self_block_id = ROOTBLOCK_INODE;
    in->content.head=0;
    in->content.tail=0;
    in->st = get_default_stat(1);

    //allocate stat block
    blocks[STATBLOCK_START] = new_block();

    for (int i=0; i<METABLOCK_NUM;i++)
        blocks[METABLOCK_START + i] = new_block();
    
    set_block_bit(ROOTBLOCK_START, 1); 
    set_block_bit(STATBLOCK_START,1);
    for (int i=0; i<METABLOCK_NUM;i++)
        set_block_bit(METABLOCK_START+i,1);

    struct stat_block * super = (struct stat_block *) blocks[STATBLOCK_START];
    super->block_num = BLOCK_NUM;
    super->block_used = 1 + 1+ METABLOCK_NUM;
    //printf("init done! %llu\n",super->block_used);
    return NULL;
}

static int oshfs_getattr(const char *path, struct stat *stbuf)
{
    //printf("getting attr\n");
    int ret = 0;
    struct filenode *node = get_filenode_by_path(path + 1);
    if(node) {
        memcpy(stbuf, &(node->link->st), sizeof(struct stat));
    }
    else
        ret = -ENOENT;
    return ret;
}

static int oshfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    //printf("reading dir:%s\n",path+1);
    struct filenode * dir = get_filenode_by_path(path + 1);
    struct filenode * node = dir->child;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    while(node) {
        //printf("  %s",node->filename);
        filler(buf, node->filename, &(node->link->st), 0);
        node = node->next;
    }
    //printf("\n");
    return 0;
}

int unlink_file(struct filenode * node) {
    if (!node) return -ENOENT;
    if (node->dir) return -ENOENT;

    if (node->prev)
        node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;
    if (node->parent)
        if (node->parent->child == node)
            node->parent->child = node->next;

    big_int block_to_free;
    big_int next_block_to_free;

    if (node->link) {
        if (node->link->st.st_nlink > 1) {
            block_to_free = 0;
            node->link->st.st_nlink--;
        }
        else {
            block_to_free = node->link->content.head;
            while (block_to_free) {
                next_block_to_free = ((struct block *)blocks[block_to_free])->next;
                free_block(block_to_free);
                block_to_free = next_block_to_free;
            }
            free_block(node->link->self_block_id);
        }
    }
    else
        return -ENOENT;

    free_block(node->self_block_id);
    return 0;
}

//Recursively
int unlink_dir(struct filenode * dir) {
    if (!dir) return -ENOENT;
    if (!dir->dir) return -ENOENT;

    if (dir->prev)
        dir->prev->next = dir->next;
    if (dir->next)
        dir->next->prev = dir->prev;
    if (dir->parent)
        if (dir->parent->child == dir)
            dir->parent->child = dir->next;

    struct filenode * child = dir->child;
    struct filenode * next_child;
    while (child) {
        //printf("  child %s\n",child->filename);
        next_child = child->next;
        if (child->dir)
            unlink_dir(child);
        else
            unlink_file(child);
        child = next_child;
    }
    free_block(dir->self_block_id);
    return 0;
}

static int oshfs_mkdir(const char *path, mode_t mode) {
    //printf("create dir:%s\n",path+1);
    if (!create_filenode(path + 1, NULL, 1))
        return -ENOENT;
    return 0;
}

static int oshfs_rmdir(const char *path) {
    return unlink_dir(get_filenode_by_path(path + 1));
    return 0;
}

static int oshfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    if (!create_filenode(path + 1, NULL, 0))
        return -ENOENT;
    return 0;
}

static int oshfs_open(const char *path, struct fuse_file_info *fi)
{
    return 0;
}

static int oshfs_rename(const char *old, const char *new) {
    printf("changing name from %s to %s\n",old,new);
    struct filenode * node = get_filenode_by_path(old + 1);
    if (!node) return -ENOENT;

    char * name = new + 1, * pos;
    while (pos = strchr(name,'/'))
        name = pos + 1;
    printf("new name:%s\n",name);

    memcpy(node->filename,name,strlen(name));
    return 0;
}

static int oshfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    //printf("writing file:%s\n",path+1);
    struct filenode *fnode = get_filenode_by_path(path+1);
    if (!fnode) return -ENOENT;
    struct inode *node = fnode->link;
    if (!node) return -ENOENT;

    //printf("write file:%s  write offset:%lu  write size:%lu\n",path,offset,size);

    struct stat_block * stat = (struct stat_block *)blocks[STATBLOCK_START];
    big_int rest_block_num = stat->block_num - stat->block_used;
    big_int request_block_num;
    if (offset + size - node->st.st_size >  + BLOCK_SIZE + 1)
        request_block_num = (offset + size - node->st.st_size - 1 + BLOCK_SIZE)/BLOCK_DATA_SIZE;
    else
        request_block_num = 0;

   //printf("rest block num:%llu  file size:%lu  need block:%llu\n",rest_block_num,node->st.st_size,request_block_num); 

    if (request_block_num > rest_block_num) {
        return -E2BIG;
   }

    big_int location_block_id = locate(node,offset);

    big_int location_bytewise = sizeof(big_int) + offset % BLOCK_DATA_SIZE;

    if (offset % BLOCK_DATA_SIZE == 0 && offset != 0)
        location_block_id = get_next_block(node,location_block_id);
    
    big_int wsize = 0;
    while (wsize < size) {
        unsigned char * location = location_bytewise + (unsigned char *)blocks[location_block_id];

        //the last block
        if (BLOCK_SIZE - location_bytewise > size - wsize) {

            //int i=0,j=size-wsize;


            memcpy(location,buf + wsize, size - wsize);
            /*
            printf("\n------last block write-----\n");
            while (i<j)
                printf("%d",location[i++]);
            printf("-------------------------\n");
            */
            wsize = size;

        }
        else {
            //printf("write progress:%llu/%llu------>",wsize,size);
            memcpy(location,buf+ wsize,BLOCK_SIZE - location_bytewise);
            wsize += BLOCK_SIZE - location_bytewise;

            //printf("%llu/%llu     ",wsize,size);
            //printf("block chain:%llu----->",location_block_id);
            location_block_id = get_next_block(node,location_block_id);
            //printf("%llu\n",location_block_id);
            location_bytewise = sizeof(big_int);
        }
    }
    size_t point = (node->st.st_size < offset)?node->st.st_size:offset;
    node->st.st_size=(node->st.st_size>point+size)?node->st.st_size:point+size;
    
    //printf("write finish, file size:%lu\n",node->st.st_size / 1024);
    return wsize;
}

static int oshfs_truncate(const char *path, off_t size)
{
    //printf("\n\n TRUNCATE!!!\n\n");
    struct filenode * fnode = get_filenode_by_path(path+1);
    if (!fnode) return -ENOENT;
    struct inode * node = fnode->link;
    if (!node) return -ENOENT;

    if (node->content.head == 0) {  //empty file
        if (size == 0) return 0;
        big_int start = allocate_block();
        node->content.head = start;
        node->content.tail = start;
    }

    big_int p = node->content.head;
    off_t point = 0;
    if (size/BLOCK_DATA_SIZE >= node->st.st_size/BLOCK_DATA_SIZE) {
        point = ((node->st.st_size - 1 + BLOCK_DATA_SIZE)/BLOCK_DATA_SIZE)*BLOCK_DATA_SIZE;
        p = node->content.tail;
    }

    while (point<size && size-point>=BLOCK_DATA_SIZE) {
        p = get_next_block(node,p);
        point += BLOCK_DATA_SIZE;
    }
    node->content.tail = p;

    struct block * p_b = (struct block *)blocks[p];
    big_int q;
    while (p_b->next) {
        q = p_b->next;
        p_b->next = ((struct block *)blocks[q])->next;
        free_block(q);
    }

    node->st.st_size = size;
    return 0;
}

static int oshfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct filenode *fnode = get_filenode_by_path(path+1);
    if (!fnode) return -ENOENT;
    struct inode *node = fnode->link;
    if (!node) return -ENOENT;
    if (offset > node->st.st_size)
        return 0;

    size = (offset + size <= node->st.st_size)?size:node->st.st_size-offset;

    big_int location_block_id = locate(node,offset);
    big_int location_bytewise = sizeof(big_int) + offset % BLOCK_DATA_SIZE;

    if (offset % BLOCK_DATA_SIZE == 0 && offset != 0) {
        location_block_id = ((struct block *)blocks[location_block_id])->next;
        if (location_block_id == 0)
            return -E2BIG;
    }

    big_int rsize = 0;

    
    while (rsize < size) {
        unsigned char * location = location_bytewise + (unsigned char *)blocks[location_block_id];
        //the last block
        if (BLOCK_SIZE - location_bytewise > size - rsize) {
            memcpy(buf+rsize, location, size - rsize);
            
            rsize = size;
        }
        else {
            memcpy(buf+rsize,location,BLOCK_SIZE - location_bytewise);
            rsize += BLOCK_SIZE - location_bytewise;
            location_block_id = ((struct block *)blocks[location_block_id])->next;
            location_bytewise = sizeof(big_int);
            if (location_block_id == 0)
                return -E2BIG;
        }
    }
    return rsize;
}

static int oshfs_unlink(const char *path)
{
    return unlink_file(get_filenode_by_path(path + 1));
}

static int oshfs_link(const char * src, const char * alias) {
    struct filenode * org = get_filenode_by_path(src + 1);
    //cannot link to null or dir
    if (!org || org->dir) return -ENOENT;

    struct inode * node = org->link;
    if (!node) return -ENOENT;

    node->st.st_nlink++;
    struct filenode * ghost = create_filenode(alias + 1 , node , 0);
    return 0;
}
/*
bool is_symlink(){
        return (attr.st_mode & S_IFLNK) == 0;
    }*/
static int oshfs_symlink(const char * src, const char * sym_alias) {
    struct filenode * soft = create_filenode(sym_alias + 1, NULL ,0);
    if (!soft) return -ENOENT;
    struct inode * node = soft->link;
    if (!node) return -ENOENT;

    node->st.st_mode = S_IFLNK | 0777;
    if (oshfs_write(sym_alias, src, strlen(src) , 0, NULL)<0) //write file name
        return -ENOENT;
    return 0;
}

static int oshfs_readlink(const char * path, char *buf, size_t size) {
    struct filenode * fnode = get_filenode_by_path(path + 1);
    if (!fnode) return -ENOENT;
    struct inode * node = fnode->link;
    if (!node) return -ENOENT;
    if (node->st.st_mode & S_IFLNK == 0) return -EACCES;

    if (size > node->st.st_size) {
        memset(buf+node->st.st_size,0,size-node->st.st_size);
        size = node->st.st_size;
    }
    if (oshfs_read(path , buf , size , 0 , NULL)<0)
        return -ENOSPC;
    return 0;
}

static int oshfs_chmod(const char * path, mode_t mode) {
    struct filenode * fnode = get_filenode_by_path(path + 1);
    if (!fnode) return -ENOENT;
    struct inode * node = fnode->link;
    if (!node) return -ENOENT;

    node->st.st_mode = mode;
    return 0;
}

static int oshfs_chown(const char * path, uid_t uid, gid_t gid) {
    struct filenode * fnode = get_filenode_by_path(path + 1);
    if (!fnode) return -ENOENT;
    struct inode * node = fnode->link;
    if (!node) return -ENOENT;

    node->st.st_gid = gid;
    node->st.st_uid = uid;
    return 0;
}

static int oshfs_utimens(const char * path , const struct timespec tv[2]) {
    struct filenode * fnode = get_filenode_by_path(path + 1);
    if (!fnode) return -ENOENT;
    struct inode * node = fnode->link;
    if (!node) return -ENOENT;

    node->st.st_atim = tv[0];
    node->st.st_mtim = tv[1];
    return 0;
}

static const struct fuse_operations op = {
    .init = oshfs_init,
    .getattr = oshfs_getattr,
    .readdir = oshfs_readdir,
    .mknod = oshfs_mknod,
    .open = oshfs_open,
    .write = oshfs_write,
    .truncate = oshfs_truncate,
    .read = oshfs_read,
    .link = oshfs_link,
    .symlink = oshfs_symlink,
    .readlink = oshfs_readlink,
    .unlink = oshfs_unlink,
    .rmdir = oshfs_rmdir,
    .mkdir = oshfs_mkdir,
    .rename = oshfs_rename,
    .chmod = oshfs_chmod,
    .chown = oshfs_chown,
    .utimens = oshfs_utimens,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &op, NULL);
}