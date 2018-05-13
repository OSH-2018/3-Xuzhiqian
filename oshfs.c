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
static const big_int mem_size = 4 * 1024 * 1024 * (size_t)1024;
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
}

struct filenode {
    char filename[MAX_FILENAME_LENGTH+1];
    content_t content;

    big_int next;
    big_int self_block_id;

    uid_t uid;
    gid_t gid;
    mode_t mode;
    big_int size;
};

struct stat_block {
    big_int block_num;
    big_int block_used;
};

struct block {
	big_int next;
	unsigned char data[BLOCK_DATA_SIZE];
};


void * blocks[BLOCK_NUM];


void * new_block() {
	void *addr = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(addr, 0, BLOCK_SIZE);
	return addr;
}

//64 bits in 1 group (big_int)
void set_block_bit(big_int block_id, bool bit) {
	big_int group_id = block_id / 64;
	big_int op=0;
	if (bit) {
		op = 1ULL << block_id % 64;
		((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK] |= op;
	}
	else {
		op = ~(1ULL << block_id % 64);
		((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK] &= op;
	}
}

big_int get_group_bits(big_int group_id) {
	return ((big_int*)blocks[METABLOCK_START + group_id/GROUP_NUM_PER_BLOCK])[group_id % GROUP_NUM_PER_BLOCK];
}

big_int search_for_free_block() {
	big_int block_id;
	big_int group_id;
	big_int group_bits;
	for (group_id = 0; ((group_bits = get_group_bits(group_id)) == 0xffffffffffffffff) && (group_id < GROUP_NUM); group_id++);

	if (group_id >= GROUP_NUM) return -1;

	block_id = group_id * 64;
	while (group_bits % 2) {
		block_id++;
		group_bits >>= 2;
	}
	return block_id;
}

big_int allocate_block() {
	big_int block_id = search_for_free_block();
	if (block_id==-1) return -1;
	blocks[block_id] = new_block();
	set_block_bit(block_id,1);

	((struct stat_block*)(blocks[0]))->block_used++;
	return block_id;
}

void free_block(big_int block_id) {
	munmap(blocks[block_id], BLOCK_SIZE);
	set_block_bit(block_id,0);
	((struct stat_block*)(blocks[0]))->block_used--;
}

//create one if no next
big_int get_next_block(struct filenode *node, big_int p) {
	if (p<0 || p>BLOCK_NUM) return -1;
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
	big_int real_max_block_id = node->size / BLOCK_DATA_SIZE;

	//location in section
	if (logical_block_id <= real_max_block_id) {
		for (int i = BLOCK_DATA_SIZE; i<offset && p!=content.tail; i+=BLOCK_DATA_SIZE)
			p = ((struct block *)blocks[p])->next;
		return p;
	}

	//location out of section
	p = node->content.tail;
	struct block * p_b;
	for (int i = ((node->size-1)/BLOCK_DATA_SIZE+1)*BLOCK_DATA_SIZE;i<offset;i+=BLOCK_DATA_SIZE)
		p = get_next_block(node,p);
	return p;
}

static struct filenode *get_filenode(const char *name)
{
    struct filenode *node = (struct filenode *)blocks[ROOTBLOCK_START];
    while(node) {
        if(strcmp(node->filename, name + 1) != 0)
            node = node->next;
        else
            return node;
    }
    return NULL;
}

static void create_filenode(const char *filename, const struct stat *st)
{
	
	struct filenode * root = (struct filenode *)blocks[ROOTBLOCK_START];

	big_int block_id_for_filenode = allocate_block();
	if (block_id_for_filenode == -1) {
		return 0;	//no more space
	}

    struct filenode *new = (struct filenode *)blocks[block_id_for_filenode];
    strncpy(new->filename, filename, MAX_FILENAME_LENGTH + 1);
    
    {
    	new->uid = st->st_uid;
    	new->gid = st->st_gid;
    	new->mode = st->st_mode;
    	new->size = st->st_size;
	}
	new->content.head = 0;
	new->content.tail = 0;
	new->self_block_id = block_id_for_filenode;
	new->next = root;
	root = new;

	return 0;
}

static void *oshfs_init(struct fuse_conn_info *conn)
{
	//allocate root pointer
	blocks[ROOTBLOCK_START] = new_block();
	(static struct filenode *) blocks[ROOTBLOCK_START] = NULL;
	set_block_bit(ROOTBLOCK_START, 1);

	//allocate stat block
	blocks[STATBLOCK_START] = new_block();

	for (int i=0; i<METABLOCK_NUM;i++)
		blocks[METABLOCK_START + i] = new_block();

	set_block_bit(STATBLOCK_START,1);
	for (int i=0; i<METABLOCK_NUM;i++)
		set_block_bit(METABLOCK_START+i,1);

    struct stat_block * super = (struct stat_block *) blocks[0];
    super->block_num = BLOCK_NUM;
    super->block_used = 1 + 1+ METABLOCK_NUM;
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
        memcpy(stbuf, node->st, sizeof(struct stat));
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
        filler(buf, node->filename, node->st, 0);
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
    create_filenode(path + 1, &st);
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

    struct stat_block * stat = (struct stat_block *)blocks[STATBLOCK_START];
    big_int rest_block_num = stat->block_num - stat->block_used;
    big_int request_block_num = (offset + size)/BLOCK_DATA_SIZE - (node->size -1)/BLOCK_DATA_SIZE;
    if (request_block_num > rest_block_num)
    	return -E2BIG;

    big_int location_block_id = locate(node,offset);
    big_int location_bytewise = sizeof(big_int) + offset % BLOCK_DATA_SIZE;
    big_int wsize = 0;
    big_int rsize;
    while (wsize < size) {

    	rsize = size - wsize;
    	unsigned char * location = location_bytewise + (unsigned char *)blocks[location_block_id];

    	//the last block
    	if (BLOCK_DATA_SIZE - location_bytewise >= rsize) {
    		memcpy(location,buf + wsize,rsize);
    		wsize = size;
    		rsize = 0;
    	}
    	else {
    		memcpy(location,buf+ wsize,BLOCK_DATA_SIZE - location_bytewise);
    		wsize += BLOCK_DATA_SIZE - location_bytewise;
    		location_block_id = get_next_block(node,location_block_id);
    		location_bytewise = sizeof(big_int);
    	}
    }
    size_t point = (node->size < offset)?node->size:offset;
    node->size=(node->size>point+size)?node->size:point+size;
    return wsize;
}

static int oshfs_truncate(const char *path, off_t size)
{
    struct filenode * node = get_filenode(path);
    if (node==NULL) return -ENOENT;

    if (node->content.head == 0) {	//empty file
    	if (size == 0) return 0;
    	big_int start = allocate_block();
    	node->content.head = start;
    	node->content.tail = start;
    }

    big_int p = node->content.head;
    off_t point = 0;
    if (size/BLOCK_DATA_SIZE >= node->size/BLOCK_DATA_SIZE) {
    	point = ((node->size - 1)/BLOCK_DATA_SIZE + 1)*BLOCK_DATA_SIZE;
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

    node->size = size;
    return 0;
}

static int oshfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct filenode *node = get_filenode(path);
    int ret = size;
    if(offset + size > node->st->st_size)
        ret = node->st->st_size - offset;
    memcpy(buf, node->content + offset, ret);
    return ret;
}

static int oshfs_unlink(const char *path)
{
    struct filenode *node = (struct filenode *)blocks[ROOTBLOCK_START];
    if (node==NULL)
    	return -ENOENT;

    big_int content_to_clear;
    big_int block_id_to_clear;
    bool flag = 0;
    if (strcmp(node->filename, path+1) == 0) {
    	content_to_clear = node->content.head;
    	block_id_to_clear = node->self_block_id;
    	(struct filenode *)blocks[ROOTBLOCK_START] = node->next;
    	flag = true;
    }
    else {
    	while (node->next) {
    		if (strcmp(node->next->filename, path+1) == 0) {
    			block_id_to_clear = node->next->self_block_id;
    			content_to_clear = node->next->content.head;
    			node->next = node->next->next;
    			free_block(block_id_to_clear);
    			flag = true;
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