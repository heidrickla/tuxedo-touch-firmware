/* Does free() on a json_write result strand its string-registry entry?
 *
 * The LEAK 31 fix rests on yes. WnmpDir_serviceField at 0x2903c disposes of the
 * handler's reply string with plain free(), and the claim is that libjson -- built
 * with JSON_MEMORY_MANAGE -- registered that pointer in a global std::map when
 * json_write called toCString, so free() releases the bytes and strands the node.
 *
 * Exercises libjson directly, so it needs no panel credentials and no emulated
 * webserver.
 *
 * The first version of this read a fixed offset from &json_write and reported 0 for
 * every arm INCLUDING a deliberate leak, which is a broken reader, not a result. So
 * this one searches for the counter instead of assuming where it is, and runs a
 * no-free arm whose count MUST rise. If the no-free arm is flat, the reader is
 * wrong and the other two numbers mean nothing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void *json_new(char type);
extern void *json_new_a(const char *name, const char *value);
extern void json_push_back(void *parent, void *child);
extern char *json_write(void *node);
extern void json_free(void *ptr);
extern void json_delete(void *node);

/* link-time addresses in libjson.so */
#define JSON_WRITE_VA 0x22890
#define STRINGS_VA    0x35cd4
#define NODES_VA      0x35c9c
#define COUNT_OFF     20

/* &json_write in THIS executable is the PLT stub, not libjson's implementation. The
 * first run computed the base from it, got 0xfffedd78, and reported 0 for every arm
 * including the deliberate leak. The control is what caught it. Read the mapping. */
static const char *libbase(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long lo;
    const char *base = NULL;
    if (!f)
        return NULL;
    while (fgets(line, sizeof line, f)) {
        /* strtoul, not sscanf: the panel's glibc has no __isoc99_sscanf, so a
           sscanf here builds on the host and fails to link against the sysroot. */
        if (strstr(line, "libjson.so") && strstr(line, "r-xp")) {
            lo = strtoul(line, NULL, 16);
            base = (const char *)lo;
            break;
        }
    }
    fclose(f);
    return base;
}

static unsigned rd(const char *p) { return *(const unsigned *)p; }

static void *build(void)
{
    void *root = json_new(5);
    json_push_back(root, json_new_a("Result", "OK"));
    return root;
}

/* Same tree, but the serialised length grows with i, so each json_write asks the
   allocator for a different size and is unlikely to be handed back the address the
   previous one just freed. The registry is keyed by pointer, so identical repeated
   allocations overwrite one key and hide the stranding. */
static void *build_n(int i)
{
    char val[512];
    int k = i % 400;
    memset(val, 'x', (size_t)k);
    val[k] = '\0';
    {
        void *root = json_new(5);
        json_push_back(root, json_new_a("Result", val));
        return root;
    }
}

static void dump(const char *label, const char *base)
{
    int off;
    printf("  %s\n", label);
    printf("    strings@0x%x:", STRINGS_VA);
    for (off = 0; off <= 28; off += 4)
        printf(" %u", rd(base + STRINGS_VA + off));
    printf("\n    nodes  @0x%x:", NODES_VA);
    for (off = 0; off <= 28; off += 4)
        printf(" %u", rd(base + NODES_VA + off));
    printf("\n");
}

int main(int argc, char **argv)
{
    int n = (argc > 1) ? atoi(argv[1]) : 20;
    int i;
    const char *base = libbase();

    if (!base) {
        printf("could not find libjson.so in /proc/self/maps\n");
        return 1;
    }
    printf("libjson base %p (the PLT stub is at %p)\n\n",
           (const void *)base, (void *)json_write);

    {   /* warm up: first call builds the registry and its guard */
        void *t = build();
        char *s = json_write(t);
        json_free(s);
        json_delete(t);
    }
    dump("after warm-up", base);

    /* CONTROL: leak on purpose. Any honest counter must rise here. */
    for (i = 0; i < n; i++) {
        void *t = build();
        (void)json_write(t);        /* never freed at all */
        json_delete(t);
    }
    dump("after leaking on purpose (control, MUST rise)", base);

    for (i = 0; i < n; i++) {
        void *t = build();
        char *s = json_write(t);
        free(s);                    /* what Barracuda does today */
        json_delete(t);
    }
    dump("after free()", base);

    for (i = 0; i < n; i++) {
        void *t = build();
        char *s = json_write(t);
        json_free(s);               /* the proposed change */
        json_delete(t);
    }
    dump("after json_free()", base);

    for (i = 0; i < n; i++) {
        void *t = build_n(i);
        char *s = json_write(t);
        free(s);                    /* free(), but each result a different size */
        json_delete(t);
    }
    dump("after free() with VARYING sizes", base);

    for (i = 0; i < n; i++) {
        void *t = build_n(i);
        char *s = json_write(t);
        json_free(s);               /* the same, disposed of correctly */
        json_delete(t);
    }
    dump("after json_free() with VARYING sizes", base);

    printf("\nn = %d per arm. Read the word that moved by n in the control;\n", n);
    printf("that is the counter. Then compare the free() and json_free() arms.\n");
    return 0;
}
