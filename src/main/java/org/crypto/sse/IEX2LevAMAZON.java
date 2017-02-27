/** * Copyright (C) 2016 Tarik Moataz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.crypto.sse;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.S3Object;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import org.apache.commons.net.util.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.WritableComparable;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;
import org.apache.hadoop.mapreduce.lib.input.KeyValueLineRecordReader;
import org.apache.hadoop.mapreduce.lib.input.LineRecordReader;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.en.EnglishAnalyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.analysis.util.CharArraySet;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class IEX2LevAMAZON {

	public static class FileNameKeyInputFormat extends FileInputFormat<Text, Text> {

		public FileNameKeyInputFormat() {
			super();
		}

		@Override
		protected boolean isSplitable(JobContext context, Path filename) {
			return false;
		}

		@Override
		public RecordReader<Text, Text> createRecordReader(InputSplit inputSplit, TaskAttemptContext taskAttemptContext)
				throws IOException, InterruptedException {

			taskAttemptContext.setStatus(inputSplit.toString());
			return new FileNameKeyRecordReader(taskAttemptContext.getConfiguration(), (FileSplit) inputSplit);
		}
	}

	public static class FileNameKeyRecordReader extends KeyValueLineRecordReader {

		private final LineRecordReader lineRecordReader = new LineRecordReader();

		private Text key = new Text();
		private Text value = new Text();

		private String fileName = new String();

		public FileNameKeyRecordReader(Configuration conf, FileSplit split) throws IOException {
			super(conf);
			fileName = split.getPath().getName();
		}

		public void initialize(InputSplit genericSplit, TaskAttemptContext context) throws IOException {
			this.lineRecordReader.initialize(genericSplit, context);
		}

		public synchronized boolean nextKeyValue() throws IOException {
			if (this.lineRecordReader.nextKeyValue()) {
				this.key = new Text(fileName);
				this.value = this.lineRecordReader.getCurrentValue();
				return true;
			}
			return false;
		}

		public Text getCurrentKey() {
			return this.key;
		}

		public Text getCurrentValue() {
			return this.value;
		}
	}

	public static class ArrayListWritable implements WritableComparable {

		private ArrayList<Text> values;

		public ArrayListWritable() {
			values = new ArrayList<Text>();
		}

		public ArrayListWritable(ArrayList<Text> values) {
			this.values = values;
		}

		public ArrayList<Text> get() {
			return values;
		}

		public void add(Text val) {
			this.values.add(val);
		}

		@Override
		public int compareTo(Object o) {
			if (!(o instanceof ArrayListWritable)) {
				throw new ClassCastException();
			}
			ArrayList<Text> newValues = (ArrayList<Text>) o;

			int compareToVal = -1;
			for (int i = 0; i < this.values.size(); ++i) {
				compareToVal = newValues.get(i).compareTo(this.values.get(i));
			}
			return compareToVal;
		}

		public String toString() {
			String outp = "";
			for (Text text : this.values) {
				outp += text + "\t";
			}
			return outp;
		}

		@Override
		public void write(DataOutput dataOutput) throws IOException {
			dataOutput.writeInt(this.values.size());

			for (Text text : values) {
				text.write(dataOutput);
			}
		}

		@Override
		public void readFields(DataInput dataInput) throws IOException {
			this.values = new ArrayList<Text>();
			for (int i = 0; i < this.values.size(); ++i) {
				Text value = new Text();
				value.readFields(dataInput);
				this.values.set(i, value);
			}

		}
	}

	/*
	 * Create a Multi-map that maps filenames and documents contents Stored in
	 * the form of a file
	 */

	public static class MLK1 extends Mapper<Text, Text, Text, Text> {
		// private final static IntWritable one = new IntWritable(1);

		private static ConcurrentHashMap<String, IntWritable> mapTable = new ConcurrentHashMap<String, IntWritable>();

		private Text fileName = new Text();
		private Text word = new Text();

		public void map(Text key, Text value, Context context) throws IOException, InterruptedException {
			String line = value.toString();

			CharArraySet noise = EnglishAnalyzer.getDefaultStopSet();
			// We are using a standard tokenizer that eliminates the stop words.
			// We can use Stemming tokenizer such Porter
			// A set of English noise keywords is used that will eliminates
			// words such as "the, a, etc"
			Analyzer analyzer = new StandardAnalyzer(noise);
			List<String> token = Tokenizer.tokenizeString(analyzer, line);
			Iterator<String> it = token.iterator();
			while (it.hasNext()) {
				word.set(it.next());
				fileName.set(key);
				if (!mapTable.containsKey(fileName.toString() + word.toString())) {
					context.write(fileName, word);
					mapTable.put(fileName.toString() + word.toString(), new IntWritable(1));
				}
			}
		}
	}

	public static class RLK1 extends Reducer<Text, Text, Text, ArrayListWritable> {

		public void reduce(Text key, Iterable<Text> values, Context context) throws IOException, InterruptedException {
			ArrayListWritable keywords = new ArrayListWritable(new ArrayList<Text>());

			for (Text val : values) {
				Text tmp = new Text(val);
				keywords.add(tmp);
			}
			context.write(key, keywords);
		}
	}

	/*
	 * Create a Multi-map that maps keywords to their filenames Stored in the
	 * form of a file
	 */

	public static class MLK2 extends Mapper<Text, Text, Text, Text> {
		static ConcurrentHashMap<String, IntWritable> mapTable = new ConcurrentHashMap<String, IntWritable>();

		private Text fileName = new Text();
		private Text word = new Text();

		public void map(Text key, Text value, Context context) throws IOException, InterruptedException {
			String line = value.toString();
			CharArraySet noise = EnglishAnalyzer.getDefaultStopSet();
			// We are using a standard tokenizer that eliminates the stop words.
			// We can use Stemming tokenizer such Porter
			// A set of English noise keywords is used that will eliminates
			// words such as "the, a, etc"
			Analyzer analyzer = new StandardAnalyzer(noise);
			List<String> token = Tokenizer.tokenizeString(analyzer, line);
			Iterator<String> it = token.iterator();
			while (it.hasNext()) {
				word.set(it.next());
				fileName.set(key);
				if (!mapTable.containsKey(fileName.toString() + word.toString())) {
					context.write(word, fileName);
					mapTable.put(fileName.toString() + word.toString(), new IntWritable(1));
				}

			}
		}

	}

	public static class RLK2 extends Reducer<Text, Text, Text, ArrayListWritable> {

		public void reduce(Text key, Iterable<Text> values, Context context) throws IOException, InterruptedException {

			ArrayListWritable fileNames = new ArrayListWritable(new ArrayList<Text>());

			for (Text val : values) {
				Text tmp = new Text(val);
				fileNames.add(tmp);
			}
			context.write(key, fileNames);
		}
	}

	/*
	 * Creation of the Local multimap
	 */

	public static class LocalMM extends Mapper<LongWritable, Text, Text, Text> {

		private Text fileName = new Text();
		private Text word = new Text();

		Configuration conf;
		String inst1;
		String inst2;
		String inst3;
		final int bigBlock = 100;
		final int smallBlock = 10;
		final int dataSize = 1000;

		public void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {

			conf = context.getConfiguration();
			inst1 = conf.get("lookup");
			inst2 = conf.get("lookup2");
			inst3 = conf.get("setKeys");
			Multimap<String, String> lookup = null;

			try {
				lookup = (Multimap<String, String>) Serializer.deserialize(Base64.decodeBase64(inst1.getBytes()));
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			Multimap<String, String> lookup2 = null;
			try {
				lookup2 = (Multimap<String, String>) Serializer.deserialize(Base64.decodeBase64(inst2.getBytes()));
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			List<byte[]> listSK = null;
			try {
				listSK = (List<byte[]>) Serializer.deserialize(Base64.decodeBase64(inst3.getBytes()));
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			String line = value.toString();
			String[] token = line.split("\\s+");
			int counter = 0;

			// First computing V_w. Determine Doc identifiers

			Set<String> VW = new TreeSet<String>();
			for (String idDoc : lookup.get(token[0])) {
				VW.addAll(lookup2.get(idDoc));
				System.out.println("Document is: " + idDoc);

			}

			Multimap<String, String> secondaryLookup = ArrayListMultimap.create();

			// here we are only interested in documents in the intersection
			// between "keyword" and "word"
			for (String word : VW) {
				Collection<String> l1 = new ArrayList<String>(lookup.get(word));
				Collection<String> l2 = new ArrayList<String>(lookup.get(token[0]));
				l1.retainAll(l2);
				secondaryLookup.putAll(word, l1);
			}

			// End of VW construction
			RR2Lev.counter = 0;
			Multimap<String, byte[]> obj = null;

			try {
				if (secondaryLookup.size() > 0) {
					obj = RR2Lev.setup(CryptoPrimitives.generateCmac(listSK.get(0), token[0]),
							secondaryLookup.keySet().toArray(new String[0]), secondaryLookup, bigBlock, smallBlock,
							dataSize);
				}
			} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
					| NoSuchProviderException | NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			word.set(Integer.toString(counter));
			fileName.set(Serializer.serialize(obj));
			context.write(word, fileName);

			counter++;

		}

	}

	/*
	 * Creation of local multi-maps
	 */

	/**
	 * @param args
	 * @throws Exception
	 */
	/**
	 * @param args
	 * @throws Exception
	 */
	@SuppressWarnings("null")
	public static void main(String[] args) throws Exception {

		// First Job
		Configuration conf = new Configuration();

		Job job = Job.getInstance(conf, "IEX-2Lev");

		job.setJarByClass(IEX2LevAMAZON.class);

		job.setMapperClass(MLK1.class);

		job.setReducerClass(RLK1.class);

		job.setMapOutputKeyClass(Text.class);

		job.setMapOutputValueClass(Text.class);

		job.setOutputKeyClass(Text.class);

		job.setNumReduceTasks(1);

		job.setOutputValueClass(ArrayListWritable.class);

		job.setInputFormatClass(FileNameKeyInputFormat.class);

		FileInputFormat.addInputPath(job, new Path(args[0]));
		FileOutputFormat.setOutputPath(job, new Path(args[1]));

		// Second Job
		Configuration conf2 = new Configuration();

		Job job2 = Job.getInstance(conf2, "IEX-2Lev");

		job2.setJarByClass(IEX2LevAMAZON.class);

		job2.setMapperClass(MLK2.class);

		job2.setReducerClass(RLK2.class);

		job2.setNumReduceTasks(1);

		job2.setMapOutputKeyClass(Text.class);

		job2.setMapOutputValueClass(Text.class);

		job2.setOutputKeyClass(Text.class);

		job2.setOutputValueClass(ArrayListWritable.class);

		job2.setInputFormatClass(FileNameKeyInputFormat.class);

		FileInputFormat.addInputPath(job2, new Path(args[0]));
		FileOutputFormat.setOutputPath(job2, new Path(args[2]));

		job.waitForCompletion(true);
		job2.waitForCompletion(true);

		// Here add your Amazon Credentials

		AWSCredentials credentials = new BasicAWSCredentials("XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX");
		// create a client connection based on credentials
		AmazonS3 s3client = new AmazonS3Client(credentials);

		// create bucket - name must be unique for all S3 users
		String bucketName = "iexmaptest";

		S3Object s3object = s3client.getObject(new GetObjectRequest(bucketName, args[4]));
		System.out.println(s3object.getObjectMetadata().getContentType());
		System.out.println(s3object.getObjectMetadata().getContentLength());
		List<String> lines = new ArrayList<String>();

		String folderName = "2";

		BufferedReader reader = new BufferedReader(new InputStreamReader(s3object.getObjectContent()));
		String line;
		int counter = 0;
		while ((line = reader.readLine()) != null) {
			// can copy the content locally as well
			// using a buffered writer
			lines.add(line);
			System.out.println(line);
			// upload file to folder
			String fileName = folderName + "/" + Integer.toString(counter);
			ByteArrayInputStream input = new ByteArrayInputStream(line.getBytes());
			s3client.putObject(bucketName, fileName, input, new ObjectMetadata());
			counter++;
		}

		Multimap<String, String> lookup = ArrayListMultimap.create();

		for (int i = 0; i < lines.size(); i++) {
			String[] tokens = lines.get(i).split("\\s+");
			for (int j = 1; j < tokens.length; j++) {
				lookup.put(tokens[0], tokens[j]);
			}
		}

		// Loading inverted index that associates files identifiers to keywords
		lines = new ArrayList<String>();
		s3object = s3client.getObject(new GetObjectRequest(bucketName, args[5]));
		System.out.println(s3object.getObjectMetadata().getContentType());
		System.out.println(s3object.getObjectMetadata().getContentLength());

		// Loading inverted index that associates keywords to identifiers

		reader = new BufferedReader(new InputStreamReader(s3object.getObjectContent()));
		while ((line = reader.readLine()) != null) {
			lines.add(line);
		}
		Multimap<String, String> lookup2 = ArrayListMultimap.create();
		for (int i = 0; i < lines.size(); i++) {
			String[] tokens = lines.get(i).split("\\s+");
			for (int j = 1; j < tokens.length; j++) {
				lookup2.put(tokens[0], tokens[j]);
			}
		}

		// Delete File
		try {
			s3client.deleteObject(new DeleteObjectRequest(bucketName, args[4]));
		} catch (AmazonServiceException ase) {
			System.out.println("Caught an AmazonServiceException.");
			System.out.println("Error Message:    " + ase.getMessage());
			System.out.println("HTTP Status Code: " + ase.getStatusCode());
			System.out.println("AWS Error Code:   " + ase.getErrorCode());
			System.out.println("Error Type:       " + ase.getErrorType());
			System.out.println("Request ID:       " + ase.getRequestId());
		} catch (AmazonClientException ace) {
			System.out.println("Caught an AmazonClientException.");
			System.out.println("Error Message: " + ace.getMessage());
		}

		/*
		 * Start of IEX-2Lev construction
		 */

		// Generation of keys for IEX-2Lev
		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter your password :");
		String pass = keyRead.readLine();

		// You can change the size of the key; Here we set it to 128

		List<byte[]> listSK = IEX2Lev.keyGen(128, pass, "salt/salt", 100000);

		// Generation of Local Multi-maps with Mapper job only without reducer

		Configuration conf3 = new Configuration();

		String testSerialization1 = new String(Base64.encodeBase64(Serializer.serialize(lookup)));
		String testSerialization2 = new String(Base64.encodeBase64(Serializer.serialize(lookup2)));

		String testSerialization3 = new String(Base64.encodeBase64(Serializer.serialize(listSK)));

		// String testSerialization2 = gson.toJson(lookup2);
		conf3.set("lookup", testSerialization1);
		conf3.set("lookup2", testSerialization2);
		conf3.set("setKeys", testSerialization3);

		Job job3 = Job.getInstance(conf3, "Local MM");

		job3.setJarByClass(IEX2LevAMAZON.class);

		job3.setMapperClass(LocalMM.class);

		job3.setNumReduceTasks(0);

		FileInputFormat.addInputPath(job3, new Path(args[2]));
		FileOutputFormat.setOutputPath(job3, new Path(args[3]));

		job3.waitForCompletion(true);

	}
}
