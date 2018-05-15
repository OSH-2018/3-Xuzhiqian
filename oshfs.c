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
#define STATBLOCK_START 1
#define METABLOCK_START 2
#define METABLOCK_NUM (BLOCK_NUM / 8 /BLOCK_SIZE)
#define GROUP_NUM (BLOCK_NUM / 64)
#define GROUP_NUM_PER_BLOCK (BLOCK_SIZE / sizeof(big_int))

struct content_t {
    big_int head;
    big_int tail;
};

struct filenode {
    char filename[MAX_FILENAME_LENGTH+1];
    struct content_t content;

    struct filenode * next;
    big_int self_block_id;

    struct stat st;
};

struct stat_block {
    big_int block_num;
    big_int block_used;
};

struct block {
    big_int next;
    char data[BLOCK_DATA_SIZE];
};


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
       //printf("use block %llu, group %llu: %llx\n",block_id,group_id,((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK] |= _op);
    }
    else {
        _op = ~(1ULL << block_id % 64);
        //printf("free block %llu, group %llu\n: %llx\n",block_id,group_id,((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK] &= _op);
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
big_int get_next_block(struct filenode *node, big_int p) {
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

big_int locate(struct filenode * node, off_t offset) {
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
    for (int i = ((node->st.st_size-1)/BLOCK_DATA_SIZE+1)*BLOCK_DATA_SIZE;i<offset;i+=BLOCK_DATA_SIZE)
        p = get_next_block(node,p);
    return p;
}

static struct filenode *get_filenode(const char *name)
{
    struct filenode *node = (struct filenode *)blocks[ROOTBLOCK_START];
    while(node) {
        if(strcmp(node->filename, name + 1) != 0)
            node = node->next;
        else {
            return node;
        }
    }
    return NULL;
}

static int create_filenode(const char *filename, const struct stat st)
{
    big_int block_id_for_filenode = allocate_block();
    if (block_id_for_filenode == -1) {
        //printf("no more space?kidding?\n");
        return 0;   //no more space
    }

    struct filenode *new = (struct filenode *)blocks[block_id_for_filenode];
    strncpy(new->filename, filename, MAX_FILENAME_LENGTH + 1);
    new->st = st;
    new->content.head = 0;
    new->content.tail = 0;
    new->self_block_id = block_id_for_filenode;
    new->next = (struct filenode *)blocks[ROOTBLOCK_START];
    blocks[ROOTBLOCK_START] = new;


    struct filenode * p = (struct filenode *)blocks[ROOTBLOCK_START];
    while (p) {
        p = p->next;
        if (p==(struct filenode *)blocks[ROOTBLOCK_START]) break;
    }

    return 0;
}

void *oshfs_init()
{
    //allocate root pointer
    blocks[ROOTBLOCK_START] = new_block();
    blocks[ROOTBLOCK_START] = NULL;

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
    int ret = 0;
    struct filenode *node = get_filenode(path);
    if(strcmp(path, "/") == 0) {
        memset(stbuf, 0, sizeof(struct stat));
        stbuf->st_mode = S_IFDIR | 0755;
    } else if(node) {
        memcpy(stbuf, &(node->st), sizeof(struct stat));
    } else {
        ret = -ENOENT;
    }
    return ret;
}

static int oshfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    struct filenode * node = (struct filenode *)blocks[ROOTBLOCK_START];
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    while(node) {
        filler(buf, node->filename, &(node->st), 0);
        node = node->next;
    }
    return 0;
}

static int oshfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    struct stat st;
    st.st_mode = S_IFREG | 0644;
    st.st_uid = fuse_get_context()->uid;
    st.st_gid = fuse_get_context()->gid;
    st.st_nlink = 1;
    st.st_size = 0;
    st.st_blksize = BLOCK_DATA_SIZE;
    st.st_blocks = 0;
    create_filenode(path + 1, st);
    return 0;
}

static int oshfs_open(const char *path, struct fuse_file_info *fi)
{
    return 0;
}

static int oshfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct filenode *node = get_filenode(path);
    if (node == NULL)
        return -ENOENT;


    //printf("write file:%s  write offset:%lu  write size:%lu\n",path,offset,size);

    struct stat_block * stat = (struct stat_block *)blocks[STATBLOCK_START];
    big_int rest_block_num = stat->block_num - stat->block_used;
    big_int request_block_num = (offset + size - node->st.st_size - 1 + BLOCK_DATA_SIZE)/BLOCK_DATA_SIZE;
   //printf("rest block num:%llu  file size:%lu  need block:%llu\n",rest_block_num,node->st.st_size,request_block_num); 
if (request_block_num > rest_block_num) {
        return -E2BIG;
   }

    big_int location_block_id = locate(node,offset);
    big_int location_bytewise = sizeof(big_int) + offset % BLOCK_DATA_SIZE;
    big_int wsize = 0;
    while (wsize < size) {
        char * location = location_bytewise + (char *)blocks[location_block_id];

        //the last block
        if (BLOCK_SIZE - location_bytewise >= size - wsize) {

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
            memcpy(location,buf+ wsize,BLOCK_SIZE - location_bytewise);
            wsize += BLOCK_SIZE - location_bytewise;
            location_block_id = get_next_block(node,location_block_id);
            location_bytewise = sizeof(big_int);
        }
    }
    size_t point = (node->st.st_size < offset)?node->st.st_size:offset;
    node->st.st_size=(node->st.st_size>point+size)?node->st.st_size:point+size;
    
    //printf("write finish, file size:%lu\n",node->st.st_size);
    return wsize;
}

static int oshfs_truncate(const char *path, off_t size)
{
    //printf("\n\n TRUNCATE!!!\n\n");
    struct filenode * node = get_filenode(path);
    if (node==NULL) return -ENOENT;

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
    struct filenode *node = get_filenode(path);
    if (node == NULL) return -ENOENT;
    if (offset > node->st.st_size)
        return 0;

    size = (offset + size <= node->st.st_size)?size:node->st.st_size-offset;

    big_int location_block_id = locate(node,offset);
    big_int location_bytewise = sizeof(big_int) + offset % BLOCK_DATA_SIZE;
    big_int rsize = 0;

    while (rsize < size) {
        //printf("read progress:%llu/%llu\n",rsize,size);
        char * location = location_bytewise + (char *)blocks[location_block_id];
        //the last block
        if (BLOCK_SIZE - location_bytewise >= size - rsize) {
            memcpy(buf+rsize, location, size - rsize);
            /*
            printf("-------------last block read------\n");
            int i=0,j=size-rsize;
            while (i<j) printf("%d ",location[i++]);
            printf("----------------------------------\n");*/

            rsize = size;
        }
        else {
            memcpy(buf+rsize,location,BLOCK_SIZE - location_bytewise);
            rsize += BLOCK_SIZE - location_bytewise;
            location_block_id = ((struct block *)blocks[location_block_id])->next;
            location_bytewise = sizeof(big_int);

            if (location_block_id == 0) return -E2BIG;
        }
    }
    return rsize;
}

static int oshfs_unlink(const char *path)
{
    struct filenode *node = (struct filenode *)blocks[ROOTBLOCK_START];
    if (node==NULL)
        return -ENOENT;

    big_int content_to_clear;
    big_int block_id_to_clear;
    int flag = 0;
    if (strcmp(node->filename, path+1) == 0) {
        content_to_clear = node->content.head;
        block_id_to_clear = node->self_block_id;
        blocks[ROOTBLOCK_START] = node->next;
        flag = 1;
    }
    else {
        while (node->next) {
            if (strcmp(node->next->filename, path+1) == 0) {
                block_id_to_clear = node->next->self_block_id;
                content_to_clear = node->next->content.head;
                node->next = node->next->next;
                free_block(block_id_to_clear);
                flag = 1;
                break;
            }
            else node = node->next;
        }
    }
    if (!flag) return -ENOENT;

    big_int next;
    while (content_to_clear) {
        next = ((struct block *)blocks[content_to_clear])->next;
        free_block(content_to_clear);
        content_to_clear = next;
    }
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
    .unlink = oshfs_unlink,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &op, NULL);
}