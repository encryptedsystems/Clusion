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

+ [Hadoop-2.7.1](http://hadoop.apache.org/releases.htm) was used for our
  distributed implementation of the IEX-2Lev setup algorithm. Earlier releases
 of Hadoop may work as well but were not tested 

Clusion was tested with Java version `1.7.0_75`.


## Implementation:

*Indexing.* Our indexer takes as input a folder that can contain pdf files,
Micorosft files such .doc, .ppt, media files such as pictures and videos as
well as raw text files such .html and .txt. The indexing step outputs two
lookup tables. The first associates keywords to document filenames while the
second associates filenames to keywords. For the indexing, we use Lucene to
tokenize the keywords and get rid of noisy words.  For this phase, Apache
Lucene, PDFBox and POI are required. For our data structures, we use Google
Guava.

*Cryptographic primitives.* All our implementations make use of the Bouncy
Castle library. The code is modular and all cryptographic primitives are
gathered in the `CryptoPrimitives.java` file.  The file contains AES-CTR,
HMAC_SHA256/512, AES-CMAC, key generation based on PBE PKCS1 and random string
generation based on SecureRandom.  In addition, it also contains an
implementation of the HCB1 online cipher from \[[BBKN07][BBKN07]\]. 



We implemented the following SSE schemes:

+ **2Lev**:  a static and I/O-efficient SSE scheme \[[CJJJKRS14][CJJJKRS14]]\. 

+ **IEX^B-2Lev**: a  worst-case optimal boolean SSE scheme \[[KM16][KM16]\].
  This implementation makes use of 2Lev as a building block.  The
disjunctive-only IEX-2Lev construction from \[[KM16][KM16]\] is a special case
of IEX^B-2Lev where the number of disjunctions is set to 1 in the Token
algorithm.

+ **ZMF**: a compact single-keyword SSE scheme 
  (with linear search complexity) \[[KM16][KM16]\]. The construction is
inspired by  the Z-IDX construction \[[Goh03][Goh03]\] but handles
variable-sized collections of Bloom filters called *Matryoshka filters*. ZMF
also makes a non-standard use of online ciphers.  Here, we implemented the
HCBC1 construction from  \[[BBKN07][BBKN07]\] but would like to replace this
with the more efficient COPE scheme from \[[ABLMTY13][ABLMTY13]\]. 

+ **IEX^B-ZMF**: a compact worst-case optimal boolean SSE scheme. Like our
  IEX^B-2Lev implementation, the purely disjunctive variant IEX-ZMF is a special case with the number of disjunctions set to 1. 

+ **IEX-2Lev-Amazon**: a distributed implementation of text indexing based on MapReduce/Hadoop
on [Amazon AWS](https://aws.amazon.com/fr/). 

+ We also plan to share our Client-Server implementation for 2Lev, IEX^B-2Lev, IEX^B-ZMF once finalized. 

## Quick Test:

For a quick test, create a folder, make sure that you have all required
libraries, store some files in the folder and enjoy!

+ to test 2Lev run `TestLocal2Lev`
+ to test IEX-2Lev run `TestLocalIEX2Lev`
+ to test IEX-ZMF run `TestLocalIEXZMF`
+ to test IEX-2Lev on Amazon run `IEX2LevAMAZON`


## References

1. \[[CJJJKRS14](https://eprint.iacr.org/2014/853.pdf)\]: D. Cash, S. Jarecki, C. Jutla, H. Krawczyk, M. Rosu, M. Steiner. *Dynamic Searchable Encryption in Very-Large Databases: Data Structures and Implementation*.

2. \[KM16\]: S. Kamara and T. Moataz. "Boolean Searchable Symmetric Encryption with Worst-Case Optimal Complexity". Available upon request. 

3. \[[Goh03](https://eprint.iacr.org/2003/216.pdf)\]: E. Goh. *Secure Indexes*. 

4. \[[ABLMTY13](https://eprint.iacr.org/2013/790.pdf)\]: E. Andreeva, A.  
Bogdanov, A. Luykx, B. Mennink, E. Tischhauser, and K. Yasuda. *Parallelizable and Authenticated Online Ciphers*. 

5. \[[BBKN07](https://cseweb.ucsd.edu/~mihir/papers/olc.pdf)\]: M. Bellare,
A. Boldyreva, L. Knudsen and C. Namprempre. *On-Line Ciphers and the Hash-CBC Constructions*.  


