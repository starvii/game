"""
patchelf --set-interpreter /glibc/2.23/64/lib/ld-linux-x86-64.so.2 baby_heap_patched
patchelf --replace-needed libc.so.6 ./libc.so.6 baby_heap_patched
"""