/*
 * Daniel Church
 * Computer Security CSCI 476
 * Lab 1
 * 1/31/17
 */

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Main {

	public Main (){
		DataInputStream dis = null;
		try {
			//Load File
			dis = new DataInputStream(new FileInputStream(new File("memorydump.dmp")));
			byte[] bytes = new byte[dis.available()];
			dis.readFully(bytes); //Read all bytes into byte[]
			
			List<String> possibleTrack1Hits = new ArrayList<String>();
			List<String> possibleTrack2Hits = new ArrayList<String>();
			
			String current = "";
			boolean inTrack1Format = false;
			boolean inTrack2Format = false;
			byte lastByte = 0;
			for(byte b : bytes){
				if(Integer.toBinaryString(b).charAt(0) != '0') //Only read ascii characters
					 if((char)b == '?') { //end of track 1 & 2
						if(!current.isEmpty()) {
							if(inTrack1Format) {
								possibleTrack1Hits.add(current + (char)b);
								inTrack2Format = true; //Start track 2 if possible
								inTrack1Format = false;
							} else if(inTrack2Format) {
								possibleTrack2Hits.add(current + (char)b);
								inTrack2Format = false;
							}
						}
						current = "";
					} else if((char)b == '%' || inTrack1Format) { //start of, or in track 1
						inTrack1Format = true;
						current += (char)b;
						if(current.length() > 1 && (char)current.charAt(1) != 'B'){ //Verify the start of track 1
							inTrack1Format = false;
							current = "";
						}
					}else if(inTrack2Format) { //In track 2
						if(current.isEmpty())
							if((char)lastByte != '?' || (char)b != ';') { //Verify the start of track 2
								current = "";
								inTrack2Format = false;
								possibleTrack1Hits.remove(possibleTrack1Hits.size()-1); //Remove from track 1 because track 2 is incorrect
							}
							current += (char)b;
					}
				lastByte = b;
			}
			
			//Track 1 syntax - %B\d{13,19}\^[a-zA-Z]{2,26}\/[a-zA-Z]{2,26}\^.+\?
			String p1 = "%B\\d{13,19}\\^[a-zA-Z]{2,26}\\/[a-zA-Z]{2,26}\\^.+\\?";
			//Track 2 syntax - ;\d{13,19}\=.+\?
			String p2 = ";\\d{13,19}\\=.{7,}\\?";
			
			//Verify correct format
			for(int i = 0; i < possibleTrack1Hits.size(); i++) {
				String t1 = possibleTrack1Hits.get(i);
				String t2 = possibleTrack2Hits.get(i);
				
				if(!(t1.matches(p1) && t2.matches(p2))) { //Eliminate if incorrect
					possibleTrack1Hits.remove(i);
					possibleTrack2Hits.remove(i);
				}
			}
			
			//Only hits with the correct format
			//Parse them
			
			//Verify matching info
			for(int i = 0; i < possibleTrack1Hits.size(); i++) {
				String t1 = possibleTrack1Hits.get(i);
				String t2 = possibleTrack2Hits.get(i);

				if(!(t1.split("%B")[1].split("\\^")[0].equals(t2.split(";")[1].split("\\=")[0]) //Matching Credit Card #
				&& t1.split("\\^")[2].substring(0, 7).equals(t2.split("\\=")[1].substring(0, 7)))) { //Additional Data Matches
					possibleTrack1Hits.remove(i);
					possibleTrack2Hits.remove(i);
				}
			}
			
			int infoNum = possibleTrack1Hits.size();
			
			//read data from correct cards
			List<Card> cards = new ArrayList<Card>();
			for(int i = 0; i < infoNum; i++){
				String t1 = possibleTrack1Hits.get(i);
				String t2 = possibleTrack2Hits.get(i);
				cards.add(new Card(i+1, t1.split("\\^")[1].split("\\/")[0] + " " + t1.split("\\^")[1].split("\\/")[1].split("\\^")[0], t1.split("%B")[1].split("\\^")[0].replaceAll("(.{4})", "$1 "), t1.split("\\^")[2].substring(2, 4) + "/" + "20" + t1.split("\\^")[2].substring(0, 2), t2.split("\\=")[1].substring(7, 11), t2.split("\\=")[1].substring(11, 14)));
			}
			
			System.out.println("There is " + infoNum + " piece(s) of credit card information in the memory data!\n");
			
			for(Card c : cards)
				printCard(c);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void printCard (Card c){
		System.out.println("<Information of the " + ordinal(c.index) + " credit card>: ");
		System.out.println("Cardholder's Name: " + c.name);
		System.out.println("Card Number: " + c.number);
		System.out.println("Expiration Date: " + c.expDate);
		System.out.println("Encrypted PIN: " + c.pin);
		System.out.println("CVV Number: " + c.CVV);
	}
	
	//src http://stackoverflow.com/questions/6810336/is-there-a-way-in-java-to-convert-an-integer-to-its-ordinal
	private static String ordinal(int i) {
	    String[] sufixes = new String[] { "th", "st", "nd", "rd", "th", "th", "th", "th", "th", "th" };
	    switch (i % 100) {
	    case 11:
	    case 12:
	    case 13:
	        return i + "th";
	    default:
	        return i + sufixes[i % 10];
	    }
	}
	
	public static void main(String[] args){
		new Main();
	}
	
	private class Card {
		
		public int index;
		public String name, number, expDate, pin, CVV;
		
		public Card (int index, String name, String number, String expDate, String pin, String CVV){
			this.index = index;
			this.name = name;
			this.number = number;
			this.expDate = expDate;
			this.pin = pin;
			this.CVV = CVV;
		}
		
	}
	
}
