# The Clusion Library

Clusion is an easy to use software library for searchable symmetric encryption
(SSE). Its goal is to provide modular implementations of various
state-of-the-art SSE schemes. Clusion includes constructions that handle
single, disjunctive, conjunctive and (arbitrary) boolean keyword search.  All
the implemented schemes have *optimal* asymptotic search complexity in the
worst-case.  

Clusion is provided as-is under the *Modified BSD License* (BSD-3). 


## Requirements:
Clusion is written in Java and has the following dependencies:

+ Bouncy Castle					https://www.bouncycastle.org/

+ Apache Lucene					https://lucene.apache.org/core/

+ Apache PDFBox					https://pdfbox.apache.org/

+ Apache POI					https://poi.apache.org/

+ Google Guava					https://poi.apache.org/

+ SizeOF (needed to calculate object size in Java)	http://sizeof.sourceforge.net/

In order to run **IEX2LevAMAZON**, hadoop-2.7.1 was used (earlier releases may work
as well but were not tested) http://hadoop.apache.org/releases.html

The sources were tested in Java version `1.7.0_75`.


## Implementation:


**Indexing.** Our indexer takes as input a folder that can contain pdf files,
Micorosft files such .doc, .ppt, media files such as pictures and videos as
well as raw text files such .html and .txt. The indexing step outputs two
lookup tables. The first associates keywords to document filenames while the
second associates filenames to keywords. For the indexing, we use Lucene to
tokenize the keywords and get rid of noisy words.  For this phase, Apache
Lucene, PDFBox and POI are required. For our data structures, we use Google
Guava.

**Cryptographic primitives.** All implementation below make use of Bouncy
Castle API. This API can be used by other APIs if required. The code is modular
and all cryptographic primitives are gathered in the CryptoPrimitives file.
The file contains AES-CTR, HMAC_SHA256/512, AES-CMAC, key generation based on
PBE PKCS1 and random string generation based on SecureRandom.  In addition, it
also contains an  implementation of the HCB1 online cipher by Bellare,
Boldyreva, Knudsen, Namprempre from *On-Line Ciphers and the Hash-CBC
Constructions* is also available. 


We implemented the following SSE schemes:

+ **2Lev**:  an implementation of the encrypted multi-map (i.e., SSE) scheme
  **2Lev** by Cash, Jaeger, Jarecki, Jutla, Krawczyk, Rosu and Steiner from
\[[CJJJKRS14][CJJJKRS14]]\. In our implementation,
we restrict ourselves to the static setting. 

+ **IEX^B-2Lev**: an implementation of the **IEX^B-2Lev** scheme which is a
  worst-case optimal boolean keyword  SSE scheme by Kamara and Moataz from
\[[KM16][KM16]\].  This implementation makes use of the **2Lev** encrypted
multi-map as a building block.  The **IEX-2Lev** scheme (a worst-case optimal
disjunctive keyword SSE scheme) from the same paper is a special case of
**IEX^B-2Lev** where the number of disjunctions is set to 1 in the Token
algorithm.  

+ **ZMF**: ZMF is a new single-keyword SSE scheme
  introduced by Kamara and Moataz from *Boolean Searchable Symmetric
Encryptiion with Worst-Case Optimal Complexity*. It has *linear* search
complexity but is highly compact. The construction is inspired by  the Z-IDX
construction from \[[Goh03][Goh03]\] but handles
a *variable*-sized collection of Bloom filters referred to as *Matryoshka
filters*. These  filters share the same hash functions for better search
efficiency, i.e., a single token can be used for multiple filters thereby
reducing the communication complexity. **ZMF** also makes a non-standard use of
online ciphers.  Here, we implemented the HCBC1 construction from
\[[BBKN07][BBKN07]\] but would like to replace this with the more efficient COPE
scheme of Elena Andreeva, Andrey Bogdanov, Atul Luykx, Bart Mennink, Elmar
Tischhauser, and Kan Yasuda from \[[ABLMTY13][ABLMTY13]\]. 

+ **IEX-ZMF**: an implementation of **IEX-ZMF**. Here, instead of using the **2Lev** construction as the main building block, we use **ZMF**. Similarly to our **IEX^B-2Lev** implementation,
we implemented **IEX^B-ZMF** which handles boolean queries. 

+ **IEX-2Lev-Amazon**: an implementation of text indexing based on MapReduce/Hadoop
on [Amazon AWS](https://aws.amazon.com/fr/). 

+ We also plan to share our Client-Server implementation for **2Lev**, **IEX^B-2Lev**, **IEX^B-ZMF** once finalized. 

## Quick Test:

For a quick test, create a folder make sure that you have all required
libraries, store some files in the folder and enjoy!

+ To run 2Lev, run TestLocal2Lev
+ To run IEX-2Lev, run TestLocalIEX2Lev
+ to run IEX-ZMF, run TestLocalIEXZMF
+ to run IEX-2Lev on Amazon run IEX2LevAMAZON



[CJJJKRS14]: https://eprint.iacr.org/2014/853.pdf "Dynamic Searchable Encryption in Very-Large Databases: Data Structures and Implementation"
[KM16]: https://eprint.iacr.org/2014/853.pdf "Boolean Searchable Symmetric Encryption with Worst-Case Optimal Complexity"
[Goh03]: https://eprint.iacr.org/2003/216.pdf "Secure Indexes"
[ABLMTY13]: https://eprint.iacr.org/2013/790.pdf "Parallelizable and Authenticated Online Ciphers"
[BBKN07]: https://cseweb.ucsd.edu/~mihir/papers/olc.pdf "On-Line Ciphers and the Hash-CBC Constructions" 


