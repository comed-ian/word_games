# word_games
The following is a write-up for the CSAW-2021 word_games challenge.  This is a standard heap note-taking challenge that is linked to glibc-2.33.so, which implements heap safe-linking.  Inspiration for the challenge is attributed to the [House of Io](https://awaraucom.wordpress.com/2020/07/19/house-of-io-remastered/) safe-link bypass strategy written by Awarau and Eyal.  

## Safe-linking
glibc-2.32+, released December, 2020, implements a new heap protection feature called safe-linking.  Safe-linking attempts to protect against typical heap exploitation strategies such as corruption of a tcache or fastbins `fw` or `bk` pointer to allow arbitrary pointer allocation (which can then be used in conjunction with a `__malloc_hook` or other overwrite to hijack execution flow).  The process involves bit shifting the linked-list pointer so that ASLR-randomized bits are xor-d with the metadata pointer.  

![safe-linking overview](https://user-images.githubusercontent.com/41522025/133334611-5e6b907a-1214-42f2-ab78-8ac06565fe2c.png) 

Source: [Check Point Research](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/)

The goal of this mitigation is to prevent attackers from leaking heap addresses and arbitrarily overwiting linked-list metadata.  While effective against a number of previously exploitable vulnerabilities, the following challenge demonstrates that the mitigation can be completely bypassed in specific scenarios.  

## Challenge Overview
The challenge requests words from the user and logs them in a linked list (`yours`).  The program also contains a secondary linked list (`mine`) which is only populated when an input contains the string `fun`.  The user has the option of suggesting a word, deleting their list, or reading the program's favorite word at that point in time.  The favorite word is the longest word containing `fun`.  Finally, the program deletes the `mine` list when four `fun` words are suggested, but interaction with the binary continues.  

## The Vuln
There are two key vulnerabilities which, when combined, permit simple bypassing of the safe-linking mitigation.  The first vulnerability is a UAF with which the value of `mine->fav` can be read even after the linked list is deleted.  The second vulnerability is an out-of-order `free()` sequence, which incorrectly frees a structure before its data.  The vulnerability is shown at the end of the following code snippet where `mine` is freed before `mine->fav`.  

```c
struct LL {
  struct node* head;
  char* fav;
};

struct LL* mine;

...

void delete_list(struct node* head) {
  struct node* tail = get_tail(head);
  struct node* tmp;
  while (tail->prev != NULL) {
    tmp = tail;
    tail = tail->prev;
    if (tmp->str) free(tmp->str);
    if (tmp != head) free(tmp);
  } 
  if (head == yours) {
    yours->next = NULL;
  }
  else {
    if (mine)       free(mine);
    if (mine->fav)  free(mine->fav);
    mine->head = NULL;
  }
}
```

`mine->fav` is populated by the pointer to `tcache_perthread_struct` when `mine` is freed because it resides at `&mine + 0x8`.  The subsequent line then frees `tcache_perthread_struct`, an unintended consequence of a simple programming mistake.  Access to overwriting `tcache_perthread_struct` puts the attacker in a powerful position, because all tcache data is *not protected by safe-linking*.  This means no heap leak is required to return an arbitrary pointer from tcache if the structure itself is modified.  Furthermore, tcache return pointers are not checked for a valid size, meaning both `__malloc_hook` and `__free_hook` are available to attack.  This methodology using the aforementioned vulnerabilities is used to easily exploit the program.  

## Exploitation
The following exploit achieves arbitrary execution without a heap leak and does not require any interaction with masked safe-link pointers.  

First, the 0x290 tcache is filled so that the incorrect freeing of `tcache_perthread_struct` pushes it into the unsorted bins.  Next, four `fun` words are suggested to trigger the second vulnerability. Then the first vulnerability is used to read `mine->fav`, which will read out the value of `tcache_perthread_struct->fw`, a libc address in main arena.  Easy calculation using offsets from the provided libc yields the addresses needed for the rest of the exploit.  Now that `tcache_perthread_struct` is in unsorted bins, any suggestion that cannot be satisfied by fastbins or tcache allocates from the beginning of the structure.  A payload is sent in to clear tcache, except for a single 0x40 chunk which points just above `__free_hook`, as shown below:

```gdb
<tcache_perthread_struct>
0x563236b3a010:	0x0000000100000000	0x0000000000000000
0x563236b3a020:	0x0000000000000000	0x0000000000000000
0x563236b3a030:	0x0000000000000000	0x0000000000000000
0x563236b3a040:	0x0000000000000000	0x0000000000000000
0x563236b3a050:	0x0000000000000000	0x0000000000000000
0x563236b3a060:	0x0000000000000000	0x0000000000000000
0x563236b3a070:	0x0000000000000000	0x0000000000000000
<tcache_perthread_struct + 0x80> 
0x563236b3a080:	0x0000000000000000	0x0000000000000000
0x563236b3a090:	0x0000000000000000	0x0000000000000000
0x563236b3a0a0:	0x00007fe827528c60	0x0000000000000000 < ptr to just above __free_hook
0x563236b3a0b0:	0x0000000000000000	0x0000000000000000
0x563236b3a0c0:	0x0000000000000000	0x0000000000000000
```

The next request fulfilled by a 0x40 allocation is returned a pointer just above `__free_hook` and simultaneously corrupts tcache for that size.  Overwriting `__free_hook` to the address of `system()` pops a shell when the string `/bin/sh` is suggested to the program and subsequently freed.  
