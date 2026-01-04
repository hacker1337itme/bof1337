# bof1337

Buffer over flow as no one did 

Overflow types & variants (C / C++) — full catalog (200 items)

Below is a broad, practical list of 200 overflow-related vulnerability types and variants you can encounter when working in C/C++. Each item is short: name — one-line description (no exploit recipes). After the list I give concise detection & mitigation guidance.

1. Stack buffer overflow — writing past a stack-allocated buffer.


2. Heap buffer overflow — writing past a heap-allocated buffer.


3. Integer overflow (wrap-around) — arithmetic wraps and produces a smaller-than-expected size.


4. Integer underflow — subtraction yields unexpectedly large unsigned value.


5. Off-by-one overflow — copying one byte too many (often null terminator).


6. Off-by-two / small-out-by-N — similar but with two or a few bytes.


7. Signedness bug causing overflow — signed-to-unsigned cast causes huge size.


8. Size_t overflow in allocation — size calculation overflows before malloc.


9. Length-check bypass via integer overflow — check succeeds but allocation too small.


10. Pointer arithmetic overflow — pointer additions go out-of-bounds.


11. Buffer overlap misuse (memcpy/memmove) — wrong direction/length leads to corruption.


12. Format-string triggered overflow — bad printf/scanf format leads to writes.


13. Use-after-free leading to overflow — freed buffer reused and overflowed.


14. Double-free causing heap corruption & overflowability.


15. Heap metadata corruption — overflow corrupts allocator metadata, enabling arbitrary write.


16. Fastbin attack variant (heap) — abusing small-bin freelist via overflow.


17. Tcache poisoning (glibc) — overflow manipulates tcache freelist.


18. Virtual table (vtable) overwrite — overflow overwrites C++ vtable pointer.


19. Overwrite of function pointers — overflow overwrites function pointer on stack/heap.


20. Return address overwrite — classic stack overflow that corrupts RET.


21. Frame pointer overwrite — overwriting saved base/frame pointer.


22. Stack canary bypass via info leak + overwrite — leak canary then overwrite.


23. Heap overflow into adjacent object — overflow of one heap object into another.


24. C++ object layout overflow — overflowing one member corrupts other members.


25. C++ std::string small-string-optimization overflow — SSO buffer overflow.


26. Wide-char (wchar_t) buffer overflow — mis-sized wide char copies.


27. UTF-8 decoding overflow — malformed sequences lead to buffer overrun.


28. Unicode normalization buffer overflow — normalization expands size unexpectedly.


29. Path-length buffer overflow — long path strings overflow fixed buffers.


30. Environment variable overflow — long env var content copied unsafely.


31. Command-line argument overflow — argv content copied into fixed buffer.


32. Stack exhaustion / recursion overflow — deep recursion exhausts stack (stack overflow).


33. Heap exhaustion leading to attacker-controlled allocation patterns — causes unsafe reuse.


34. Read() / recv() without bounds — performing read into buffer with wrong length.


35. scanf("%s") / gets() overflow — unsafe input functions that don't bound.


36. strcpy/strcat misuse — no bounds checks cause overflow.


37. sprintf / vsprintf misuse — format writers that don't limit size.


38. memcpy with wrong length param — copying more bytes than source/destination fit.


39. memmove misuse when overlapping — miscalculating lengths with overlapping regions.


40. strcat/strncat off-by-one misuse — incorrect size handling in strncat.


41. strncpy misuse (non-terminated) causing overflow later — recent writes assume NUL.


42. fgets misuse ignoring newline/NUL — incorrect post-processing errors.


43. snprintf misuse assuming return non-negative — truncation not detected.


44. Realloc size miscalculation — new size calculations overflow.


45. calloc multiplication overflow — count*size overflow before calloc call.


46. malloc(0) ambiguity exploited — platform-dependent behavior enables edge-case overflow.


47. Integer sign extension during casting — negative to large positive size.

48. Boundary-check race (TOCTOU) — check-then-use race allows overflow.


49. Multithreaded race on buffer length/ownership — concurrent writes leading to overflow.


50. IPC/pipe message overflow — reading protocol message into fixed buffer without validation.


51. Network packet length field overflow — attacker sets length larger than buffer.


52. TLS/SSL record parsing overflow — malformed records overflow parser buffers.


53. File-parsing overflow (images, audio) — crafted file triggers parser overflow.


54. Archive (zip/tar) header length overflow — archive metadata used to allocate too-small buffer.


55. XML/JSON parser overflow — crafted large fields or nested expansions.


56. Recursive-descent parser stack overflow — deep nesting in parsers.


57. Regular-expression backtracking overflow — catastrophic blowups causing resource exhaustion.


58. URL-decoding overflow — percent-decoding enlarges data beyond buffer.


59. Base64 decoding overflow — incorrect output size calc allows overflow.


60. Unicode-to-ASCII conversion overflow — expansion mishandled.


61. Locale-dependent widen/narrow overflow — character conversions misestimate size.


62. snprintf return misuse leading to overflow — trusting return value incorrectly.


63. strcat with computed remaining length wrong — forgetting to subtract NUL.


64. String-formatting loops that append without limit — iterative append until overflow.


65. Buffer overflow via user-controlled offset — index calculations not checked.


66. Indexing with negative values cast to large unsigned — negative index becomes huge.


67. Array index multiplication overflow — index * sizeof(type) overflows.


68. memcpy from untrusted length read — using attacker-provided length directly.


69. memcmp or strncmp misuse allowing OOB read then OOB write.


70. Heap buffer overflow via C++ new[] mis-sizing — wrong element count.


71. Placement new used with insufficient buffer — overflow when constructing objects.


72. Stack variable-length array overflow (VLAs) — large VLA allocation on stack.


73. alloca() stack overflow — dynamic stack allocation too large.


74. Buffer overflow due to incorrect structure packing — wrong offsetof calculations.


75. Malformed pointer arithmetic in struct-to-byte conversions — leading to OOB.


76. Integer-to-pointer cast overflow — converts large integer to pointer out-of-bounds.


77. Pointer truncation on 64-bit/32-bit cast — high bits lost leading to wrong addressing.


78. Buffer overflow from wrong assumptions about sizeof(type) — e.g., wchar_t vs char.


79. Miscalculated padding when serializing — deserialization overflows target.


80. Unchecked length from third-party library — trusting external size fields.


81. Legacy API misuse (Windows API) causing overflow — e.g., lstrcpy without size.


82. Unicode BOM handling overflow — BOM causes shift in pointer/size miscalc.


83. Integer overflow in hash table resizing — new size smaller than needed.


84. Stack buffer overflow via alloca in loop — cumulative allocations overflow.


85. Overwriting stack-allocated temporaries — mis-scoped pointers used after buffer ends.


86. Buffer overflow via format specifier length modifiers (%n misuse) — format can write.


87. %n format string attack — attackers control format to write arbitrary counts.


88. Integer overflow in CRC/length check bypass — truncated checksum allows overflow.


89. Memory mapping (mmap) mis-calculated sizes — oversized mapping used incorrectly.


90. Unbounded memcpy in kernel drivers — kernel-space overflow vulnerability.


91. Kernel stack overflow — driver or syscall causes kernel stack corruption.


92. Kernel heap overflow — overflow in kernel kmalloc area.


93. User-to-kernel copy misuse (copy_from_user) — length validation errors cause overflow.


94. IOCTL handler length miscalculation — user input overflows kernel buffer.


95. Buffer overflow via shared memory segments — wrong region size assumed.


96. Shared library symbol table overflow — malformed ELF causing overflow during load.

97. Dynamic linker (ld.so) parsing overflow — crafted ELF sections overflow loader buffers.


98. C++ virtual base pointer (vbptr) overwrite — corrupts C++ multiple inheritance internals.


99. C++ RTTI/typeinfo corruption via overflow — runtime type info corrupted.


100. Exception object overflow during throw/catch — unexpected sizes in exception handling.


101. Std::vector resize/assign misuse — using larger size without checking leading to overflow.


102. Out-of-bounds iterator arithmetic — iterator arithmetic moves past container end.


103. Std::string::data() misuse when non-null-terminated — assuming NUL terminator.


104. Binary protocol length field overflow (wrap-to-zero) — causes tiny allocation for big payload.


105. Archive-extraction path traversal plus buffer overflow — long combined paths overflow buffers.


106. Environment PATH or classpath long entries causing overflow in loader.


107. Malloc metadata overwrite via bytewise overflow — corrupt top chunk size fields.


108. Heap reuse after overflow with crafted payload — attacker-controlled pointers used.


109. Memory pool (custom allocator) overflow — custom allocators with fixed slabs overflowed.


110. Buffer overflow in serialization/deserialization of objects — reconstructed object too large.


111. Buffer overflow via memcpy of file contents into static buffer — no bounds check.


112. Overflow via incorrect assumption about network MTU — user-controlled fragmentation.


113. NUL-byte injection to bypass terminator checks then overflow later.


114. Encoding conversion worst-case growth ignored — e.g., ISO-8859 to UTF-8 expansion.


115. Large-format macro expansion overflow in compile-time generated code — source-level bug.


116. Template metaprogramming recursion causing compile-time stack exhaustion (less runtime, but relevant).


117. Overrun when copying wide structures across ABI boundaries — mismatch in packing.


118. Buffer overflow in printf-family with user-supplied format and width modifiers.


119. Overwriting C++ virtual function table pointer via heap overflow in polymorphic object.


120. Buffer overflow from mis-parsed length-delimited protobuf/ASN.1 messages.


121. Unchecked integer multiplication for buffer length (count * size) — multiplication overflow.


122. User-supplied negative length interpreted as large unsigned — leads to huge memcopy.


123. Overflows during bit-shift operations creating too-large sizes.


124. Bitfield packing assumptions causing adjacent-field overwrite.


125. Overflow because of incorrect endianness assumptions when computing sizes.


126. Buffer overflow in command parser for shell-like input — long tokens overflow.


127. Overflow in logging subsystem when formatting untrusted strings.


128. Stack buffer overflow via variable-length formatted logging without limit.


129. Buffer overflow via repeatedly reading until delimiter that never appears.


130. Overflow by concatenation in protocol assembly without cap.


131. Overflow in encryption padding routines (incorrect checks) — memory disclosure or overflow.


132. Off-by-one in memcpy when copying structure with trailing NUL.


133. Uninitialized length used in memcpy — reading garbage length causes overflow.


134. Overflow via mistaken use of sizeof(pointer) instead of sizeof(*pointer).


135. Overflow in custom string classes lacking bounds checks.


136. Overflow from using strlen on non-NUL-terminated data to compute copy length.


137. Buffer overflow in C++ iostreams via operator>> into fixed buffer.


138. Heap overflow due to incorrect alignment rounding when allocating.


139. Overflow via format-string width specifiers parsed from untrusted input.


140. Buffer overflow in JSON serializer when predicting buffer size incorrectly.


141. Overflow in database client parsing (protocol fields) — large column values.


142. Buffer overflow in compression library (zlib/gzip) from corrupted stream.


143. Integer overflow in checksum/addition leading to smaller buffer allocation.

144. Integer overflow in pointer difference computation resulting in negative sizes.


145. Buffer overflow due to forgetting to reserve space for NUL in string APIs.


146. Overflow when concatenating path and filename without checking combined length.


147. Overflow in SVG/HTML parser due to entity expansion (billion laughs) leading to huge buffers.


148. Heap overflow via COW (copy-on-write) mishandling in custom memory systems.


149. Overflow triggered by malformed metadata (e.g., EXIF) enlarging claimed size.


150. Buffer overflow in configuration file parsing — unbounded token length.


151. Buffer overflow in regex library when handling extreme patterns.


152. Overflow from casting long double to double creating unexpected rounding and lengths (edge-case).


153. Buffer overflow in base conversion routines when results longer than predicted.


154. Overflows in 3rd-party plugins badly trusting plugin-provided sizes.


155. Overflow in clipboard handling code copying huge clipboard contents.


156. Overflow while copying process environment for spawn/exec calls.


157. Buffer overflow in serialization of polymorphic objects (wrong vtable/size).


158. Stack overflow via alloca in a loop that depends on attacker input.


159. Buffer overflow in Unicode normalization library from crafted decomposition sequences.


160. Off-by-one when slicing arrays via start/end indices inclusive/exclusive confusion.


161. Buffer overflow when deserializing pointers/offsets from untrusted data.


162. Overflow in URL canonicalization routines through repeated percent-decoding.


163. Buffer overflow via mis-declared function prototypes/variadic mismatch in C (undeclared prototype).


164. Integer overflow when combining flags shifted into a size field.


165. Overflow caused by improper use of memchr/strchr results as length.


166. Buffer overflow in custom memcpy/fast copy routines with wrong block counts.


167. Overflow when computing remaining buffer as (end - ptr) but ptr modified elsewhere.


168. Buffer overflow via unexpected binary input in text-mode parsers.


169. Heap overflow via pointer arithmetic beyond allocated object in custom containers.


170. Out-of-bounds write from incorrect loop bounds (i <= n vs i < n).


171. Buffer overflow via miscalculated index in modulo arithmetic (negative mod).


172. Integer overflow in timestamp or time_t arithmetic leading to bad size.


173. Buffer overflow in GUI libraries when handling long widget names or labels.


174. Buffer overflow via incorrect reading of length-prefixed TLV elements.


175. Overflow in UTF-16 surrogate pair handling that expands to more code units.


176. Buffer overflow from concatenating translated strings that expand at runtime.


177. Overflow in memory-mapped file reads where file length changed after mmap.


178. Buffer overflow via malicious environment locale variables changing size expectations.


179. Buffer overflow in device driver IO handling due to misread user lengths.


180. Heap overflow in custom reference-counted object when refcount wrap occurs.


181. Overflow during base conversion of extremely large integer strings into binary buffers.


182. Buffer overflow in event loop message handling where length field not validated.


183. Buffer overflow in canonical path resolution with many "../" components causing expansion.


184. Integer overflow in bitmap/bitset size calculation leading to too-small allocation.


185. Buffer overflow via mis-sized cryptographic key buffers when decoding key blobs.


186. Overflow from C struct copying where source contains larger version than expected.


187. Buffer overflow because of wrong ABI assumptions between modules compiled with different options.


188. Buffer overflow due to unsupported character encodings increasing byte-per-char.


189. Buffer overflow via incorrectly parsed multipart/form-data boundaries.


190. Off-by-one in checksum loops causing last byte to be overwritten.


191. Buffer overflow in logging frameworks when expanding user-supplied format with large field widths.

192. Buffer overflow through poor validation in RPC/serialization frameworks.


193. Overflow in image format decoder due to width*height multiplication overflow.


194. Buffer overflow via crafted metadata in video/container formats (MKV/MP4).


195. Integer overflow in allocation for adjacency matrices (n * n overflow).


196. Buffer overflow from misuse of strncpy with length equal to destination size (no NUL).


197. Buffer overflow in email/MIME parsers with large headers or long lines.


198. Overflow in certificate parsing libraries handling extremely long fields.


199. Buffer overflow via incorrect assumptions about maximum domain length in DNS code.


200. Logic-flaw-driven overflow — business logic errors result in unchecked size growth.




---

Quick detection checklist

Static analysis (clang-tidy, cppcheck, Coverity, commercial SAST) — identify suspicious length arithmetic, dangerous functions, casts.

Fuzzing (AFL++, libFuzzer) — target parsers, file formats, network input.

AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan), MemorySanitizer during testing.

Dynamic analysis (Valgrind, Dr. Memory) for heap/stack misuse.

Compiler warnings enabled (-Wall -Wextra -Wconversion -Wformat-security).

Unit tests with edge-case, huge, malformed inputs.

Code review focusing on length arithmetic, casts, and third-party inputs.

Runtime checks: guardrails for length fields, saturating arithmetic checks.


Quick mitigations & best practices

Prefer safe APIs: snprintf, strlcpy/strlcat (where available), bounded memcpy_s variants.

Always validate lengths from untrusted sources before allocation/reads.

Check for multiplication overflow: use if (b != 0 && a > SIZE_MAX / b) error.

Use size-aware types (size_t) and be careful with signed/unsigned mixing.

Adopt compiler mitigations: stack canaries, ASLR, DEP/NX, PIE builds.

Harden allocator: use hardened malloc implementations (tcmalloc hardened, glibc fortify).

Enable compiler fortify/fortify-source, FORTIFY_SOURCE=2.

Use sanitizers (ASan/UBSan) in CI and fuzzing harnesses.

Apply least privilege, sandbox parsing components, run parsers in separate processes.

Use modern C++ containers and RAII (std::vector, std::string) with bounds checks where feasible.

Avoid dangerous C functions (gets, strcpy, sprintf, scanf("%s")).

Adopt code review checklists focused on overflows and integer arithmetic.



---
