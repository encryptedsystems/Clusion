# The Clusion Library

Clusion is an easy to use software library for searchable symmetric encryption
(SSE). Its goal is to provide modular implementations of various
state-of-the-art SSE schemes. Clusion includes constructions that handle
single, disjunctive, conjunctive and (arbitrary) boolean keyword search.  All
the implemented schemes have *sub-linear* asymptotic search complexity in the
worst-case.  

Clusion is provided as-is under the *GNU General Public License v3 (GPLv3)*. 


## Implementation

*Indexing.* The indexer takes as input a folder that can contain pdf files,
Micorosft files such .doc, .ppt, media files such as pictures and videos as
well as raw text files such .html and .txt. The indexing step outputs two
lookup tables. The first associates keywords to document filenames while the
second associates filenames to keywords. For the indexing, we use Lucene to
tokenize the keywords and get rid of noisy words.  For this phase, Apache
Lucene, PDFBox and POI are required. For our data structures, we use Google
Guava.

*Cryptographic primitives.* All the implementations make use of the Bouncy
Castle library. The code is modular and all cryptographic primitives are
gathered in the `CryptoPrimitives.java` file.  The file contains AES-CTR,
HMAC_SHA256/512, AES-CMAC, key generation based on PBE PKCS1 and random string
generation based on SecureRandom.  It also contains a synthetic IV AES encryption and AES based authenticated encryption. 
In addition, it also contains an
implementation of the HCB1 online cipher from \[[BBKN07][BBKN07]\]. 



The following SSE schemes are implemented:

+ **2Lev**:  a static and I/O-efficient SSE scheme \[[CJJJKRS14][CJJJKRS14]]\. 

+ **Dyn2Lev**:  a dynamic variation of \[[CJJJKRS14][CJJJKRS14]], comes with two instantiations, a first instantiation that 
only handles add operations, and a second one that handles delete operations in addition. Both instantiations have forward-security guarantees but at the cost of more interactions and non-optimality (in the case of delete). 

+ **BIEX-2Lev**: a  worst-case sub-linear boolean SSE scheme \[[KM17][KM17]\].
  This implementation makes use of 2Lev as a building block.  The
disjunctive-only IEX-2Lev construction from \[[KM17][KM17]\] is a special case
of IEX^B-2Lev where the number of disjunctions is set to 1 in the Token
algorithm.

+ **ZMF**: a compact single-keyword SSE scheme 
  (with linear search complexity) \[[KM17][KM17]\]. The construction is
inspired by  the Z-IDX construction \[[Goh03][Goh03]\] but handles
variable-sized collections of Bloom filters called *Matryoshka filters*. ZMF
also makes a non-standard use of online ciphers.  Here, we implemented the
HCBC1 construction from  \[[BBKN07][BBKN07]\] but would like to replace this
with the more efficient COPE scheme from \[[ABLMTY13][ABLMTY13]\]. 

+ **BIEX-ZMF**: a compact worst-case optimal boolean SSE scheme. Like our
  IEX^B-2Lev implementation, the purely disjunctive variant IEX-ZMF is a special case with the number of disjunctions set to 1. 

+ **IEX-2Lev-Amazon**: a distributed implementation of text indexing based on MapReduce/Hadoop
on [Amazon AWS](https://aws.amazon.com/fr/). 

+ **Dls^D**: a dual secure (breach resistant and forward private) structured encryption scheme \[[AKM19][AKM19]\].
+ We also plan to share our Client-Server implementation for 2Lev, Dyn2Lev, IEX^B-2Lev, IEX^B-ZMF once finalized. 

## Build Instructions

+ Install Java (1.7 or above)
+ Install Maven (3.3.9 or above)
+ Download/Git clone Clusion
+ Run below commands to build the jar

	`cd Clusion`
	
	`mvn clean install`
	
	`cd target`
	
	`ls Clusion-1.0-SNAPSHOT-jar-with-dependencies.jar`
	
+ If the above file exists, build was successful and contains all dependencies

## Quick Test

For a quick test, create folder and store some input files, needed jars and test classes are already created

+ export Java classpath

	run `export CLASSPATH=$CLASSPATH:/home/xxx/Clusion/target:/home/xxx/Clusion/target/test-classes`
	
	Ensure the directory paths are correct in the above
	
+ to test 2Lev (response-revealing)

	run `java org.crypto.sse.TestLocalRR2Lev`	
	
+ to test 2Lev (response-hiding)

	run `java org.crypto.sse.TestLocalRH2Lev`	
	
+ to test DynRH2Lev (response-hiding)

	run `java org.crypto.sse.TestLocalDynRH2Lev`	
	
+ to test DynRH (response-hiding)

	run `java org.crypto.sse.TestLocalDynRH`		

+ to test ZMF 

	run `java org.crypto.sse.TestLocalZMF`	
	
+ to test IEX-2Lev 

	run `java org.crypto.sse.TestLocalIEX2Lev`
	
+ to test IEX-2Lev (response-hiding)

	run `java org.crypto.sse.TestLocalIEXRH2Lev` 
	
+ to test IEX-ZMF 

	run `java org.crypto.sse.TestLocalIEXZMF`
	
+ to test IEX-2Lev on Amazon 

	run `java org.crypto.sse.IEX2LevAMAZON`


## Documentation

Clusion currently does not have any documentation. The best way to learn how to
use the library is to read through the source of the test code:

+ `org.crypto.sse.TestLocalRR2Lev.java`
+ `org.crypto.sse.TestLocalRH2Lev.java`
+ `org.crypto.sse.TestLocalDynRH2Lev.java`
+ `org.crypto.sse.TestLocalDynRH.java`
+ `org.crypto.sse.TestLocalZMF.java`
+ `org.crypto.sse.TestLocalIEX2Lev.java`
+ `org.crypto.sse.TestLocalIEXRH2Lev.java`
+ `org.crypto.sse.TestLocalIEXZMF.java`

## Requirements
Clusion is written in Java.

Below are Dependencies added via Maven (3.3.9 or above) , need not be downloaded manually

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

## References

1. \[[CJJJKRS14](https://eprint.iacr.org/2014/853.pdf)\]:  *Dynamic Searchable Encryption in Very-Large Databases: Data Structures and Implementation* by D. Cash, J. Jaeger, S. Jarecki, C. Jutla, H. Krawczyk, M. Rosu, M. Steiner.

2. \[[KM17](https://eprint.iacr.org/2017/126.pdf)\]: :  *Boolean Searchable Symmetric Encryption with Worst-Case Sub-Linear Complexity* by S. Kamara and T. Moataz. 

3. \[[Goh03](https://eprint.iacr.org/2003/216.pdf)\]: *Secure Indexes* by E. Goh. 

4. \[[ABLMTY13](https://eprint.iacr.org/2013/790.pdf)\]: *Parallelizable and
   Authenticated Online Ciphers* by E. Andreeva, A.  Bogdanov, A. Luykx, B.
Mennink, E. Tischhauser, and K. Yasuda. . 

5. \[[BBKN07](https://cseweb.ucsd.edu/~mihir/papers/olc.pdf)\]:  *On-Line
   Ciphers and the Hash-CBC Constructions* by M. Bellare, A. Boldyreva, L.
Knudsen and C. Namprempre.

6. \[[AKM19](https://eprint.iacr.org/2018/195.pdf)\]: *Breach-Resistant Structured Encryption* by 
	G. Amjad, S. Kamara and T. Moataz.


[CJJJKRS14]: https://eprint.iacr.org/2014/853.pdf
[KM17]: https://eprint.iacr.org/2017/126.pdf
[Goh03]: https://eprint.iacr.org/2003/216.pdf
[ABLMTY13]: https://eprint.iacr.org/2013/790.pdf
[BBKN07]: https://cseweb.ucsd.edu/~mihir/papers/olc.pdf
[AKM19]: https://eprint.iacr.org/2018/195.pdf
