package org.crypto.sse;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import org.mapdb.DB;
import org.mapdb.DBMaker;

public class TestDynRR {

	
	public static void main(String[] args) throws Exception {
		
		
		
		
		// init
		DB db = DBMaker.fileDB("test.db").fileMmapEnable().fileMmapPreclearDisable()
				.allocateStartSize(124 * 1024 * 1024).allocateIncrement(5 * 1024 * 1024).make();
		
		ConcurrentMap<String, byte[]> dictionary = (ConcurrentMap<String, byte[]>) db.hashMap("test").createOrOpen();		
		
		byte[] sk = new byte[32];
		
		String SN = "X4238y57y78234";
		String countyID = "00000000000000000000000000001562";

		System.out.println(countyID.getBytes("UTF-8").length);

		
		
		Map<String, String> lookup = new HashMap<String, String>();		
		lookup.put(SN, countyID);
		
		
		// creation of the update token	
		Map<String, byte[]> utk  = DynRR.updateToken(sk, lookup);
		
		
		// update
		DynRR.update(dictionary, utk);
		
		// search token
		byte[][] stk = DynRR.searchToken(sk, SN);
		
		
		//query operation
		byte[] encryptedResult = DynRR.query(stk[0], dictionary);
		
		//resolve operation
		String plaintextCounty = DynRR.resolve(stk[1], encryptedResult);
		
		
		System.out.println(plaintextCounty);

		// close the database
		db.close();
		
	}
	
	
}
