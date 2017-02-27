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

/*Partitioning decreases the size of the inverted index.
 * Avoid using the partitioning method if the gain will
 * be small or null
 * 
 * This technique is first introduced to gain space but 
 * not enabled by default, and is still
 * under more research investigation.
 * 
 */
package org.crypto.sse;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Partition {

	private Partition() {
	}

	public static Multimap<Integer, String> partitioning(Multimap<String, String> lookup) {

		// Partitions Creation
		Set<String> keys = lookup.keySet();

		int partitionId = 0;
		Multimap<Integer, String> partitions = ArrayListMultimap.create();
		int counter2 = 0;

		for (String key : keys) {
			Set<Integer> keys2 = partitions.keySet();
			List<String> inter = (List<String>) lookup.get(key);
			List<String> interTMP = new ArrayList<String>(inter);

			System.out.println("Step number: " + counter2++ + "Number of keywords " + keys.size());

			Set<String> set = new HashSet<String>(interTMP);
			Multimap<Integer, String> partitionsTMP = ArrayListMultimap.create();

			for (Integer key2 : keys2) {

				if (!set.isEmpty()) {
					Set<String> tmp = new HashSet<String>(partitions.get(key2));

					Set<String> intersection = Sets.intersection(tmp, set);

					Set<String> difference;

					if (intersection.isEmpty()) {
						difference = tmp;
					} else {
						difference = Sets.difference(tmp, intersection);
						set = Sets.difference(set, intersection);

					}

					if (!difference.isEmpty()) {
						partitionId = partitionId + 1;
						partitionsTMP.putAll(partitionId, difference);
					}

					if (!intersection.isEmpty()) {
						partitionId = partitionId + 1;
						partitionsTMP.putAll(partitionId, intersection);
					}

				} else {
					partitionId = partitionId + 1;
					partitionsTMP.putAll(partitionId, new HashSet<String>(partitions.get(key2)));
				}

			}

			interTMP = new ArrayList<String>(set);

			if (!interTMP.isEmpty()) {

				partitionId = partitionId + 1;
				partitionsTMP.putAll(partitionId, interTMP);

			}

			partitions = ArrayListMultimap.create(partitionsTMP);
			partitionsTMP.clear();
			interTMP.clear();

		}

		System.out.println("Partitions size " + partitions.keySet().size());
		System.out.println("\n");

		return partitions;
	}

}
