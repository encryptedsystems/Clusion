package org.crypto.sse;

import java.io.*;




/**
 * Serialize/Deserialize a byte array
 * by Thomas Mueller http://stackoverflow.com/users/382763/thomas-mueller
 */
public class Serializer {
	
public static byte[] serialize(Object obj) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ObjectOutputStream os = new ObjectOutputStream(out);
    os.writeObject(obj);
    return out.toByteArray();
}
public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    ObjectInputStream is = new ObjectInputStream(in);
    return is.readObject();
}



}