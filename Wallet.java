/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */

/*
 */

/*
 * @(#)Wallet.java	1.11 06/01/03
 */

package com.oracle.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;


public class Wallet extends Applet {

    /* constants declaration */

    // code of CLA byte in the command APDU header
    final static byte Wallet_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte RST_PIN_Counter = (byte) 0x2C;
    final static byte UP_PUK = (byte) 0x60;
    final static byte CALC_MAC = (byte) 0x61;
    final static byte UP_DES_KEY = (byte) 0x70;
    // maximum balance
    final static short MAX_BALANCE = 0x7FFF;
    // maximum transaction amount
    final static byte MAX_TRANSACTION_AMOUNT = 127;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    
    // signal the the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    final static short SW_INVALID_PUK = 0x6A86;
    final static short SW_INVALID_PUK_SIZE = 0x6A87;
    final static short SW_WRONG_MAC = 0x6A88;

    /* instance variables declaration */
    OwnerPIN pin;
    short balance;
    private static final byte[] PUK= { 0x09, 0x09,  0x09,  0x09, 0x09, 0x09, 0x09, 0x09};
    byte[] keyData = { (byte) 0x11, (byte) 0x33, (byte) 0x22, (byte) 0x05,
    		(byte) 0x44, (byte) 0x77, (byte) 0x06,(byte) 0x08 };
    byte[] receivedMac= new byte[8];
    byte[] generatedMac= new byte[8];
    byte[] receivedKey= new byte[8];
    private DESKey deskey;
    private Signature sig;
    
    private Wallet(byte[] bArray, short bOffset, byte bLength) {

        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        short keyLength = KeyBuilder.LENGTH_DES;
        deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, keyLength, false);
        
        
        deskey.setKey(keyData, (short) 0);
        
        sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);
        
        
        
        
        register();

    } // end of the constructor

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        new Wallet(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {

        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;

    }// end of select method

    @Override
    public void deselect() {

        // reset the pin value
        pin.reset();

    }

    @Override
    public void process(APDU apdu) {

        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;	
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            case RST_PIN_Counter:
            	reset_pin_try_counter(apdu);
            	return;
            case UP_PUK:
            	update_puk(apdu);
            	return;
            case CALC_MAC:
            	cal_MAC(apdu);
            	return;	
            case UP_DES_KEY:
            	update_des_key(apdu);
            	return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    } // end of process method
    
    private void update_des_key(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
    	//verify PUK
    	
        short isEqual=  Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, PUK, (short) 0,(short)8);
         
         if (isEqual==0) {
          	 pin.resetAndUnblock();
          }
          else {
          	ISOException.throwIt(SW_INVALID_PUK); 
          }
    	
    	
    	
    	//received DES key
    	
         Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA+8+1) , receivedKey ,(short) 0, (short)8);
         
         ////change DES key
         
         
        
         deskey.setKey(receivedKey, (short)0);
    }
    
    private void cal_MAC (APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        short le = apdu.setOutgoing();

        if (le < (8)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        apdu.setOutgoingLength((byte) (8));
        
        //Calculate MAC 
        
        sig.init(deskey, Signature.MODE_SIGN);
        sig.sign(buffer, (short)ISO7816.OFFSET_CDATA,  (short) byteRead, buffer,  (short)0);
       
        apdu.sendBytes((short) 0, (short) 8);
        
    }
    
     
    private void update_puk (APDU apdu) {
    	
    	
    	byte[] buffer = apdu.getBuffer();
    	byte byteRead = (byte) (apdu.setIncomingAndReceive());
    	//verify puk
        short isEqual=  Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, PUK, (short) 0,(short)8);
         
         if (isEqual==0) {
          	 pin.resetAndUnblock();
          }
          else {
          	ISOException.throwIt(SW_INVALID_PUK); 
          }
        
    	if(byteRead-8 ==8) {
    	for(byte i=0;i<8;i++) {
    		PUK[i]=buffer[ISO7816.OFFSET_CDATA+8+i];
    	}
    	}
    	else {
    		 ISOException.throwIt(SW_INVALID_PUK_SIZE);
    	}
      	
    }
   
    private void reset_pin_try_counter(APDU apdu) {
    	
    	byte[] buffer = apdu.getBuffer();
    	
 	   
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
  
     
        short isEqual=  Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, PUK, (short) 0,byteRead);
       
       if (isEqual==0) {
        	 pin.resetAndUnblock();
        }
        else {
        	ISOException.throwIt(SW_INVALID_PUK); 
        }
        
    	
    }
    private void credit(APDU apdu) {
    	
        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        // Lc byte denotes the number of bytes in the
        // data field of the command APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        if ((numBytes != 9) ) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        ////////////////////////////////////////////[Start] security operations////////////////////////////////////////////////////
        //get MAC and store it in receivedMac
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA+1) , receivedMac ,(short) 0, (short)8);    		
    	//verify MAC {CLA,INS,P1,P2,LC,DATA}
        
        sig.init(deskey, Signature.MODE_VERIFY);
        boolean isMacValid = sig.verify(buffer, (short)0, (short)(ISO7816.OFFSET_CDATA+1),
        		receivedMac,(short)0,(short)receivedMac.length);
        
        if (!isMacValid) {
        	
        	ISOException.throwIt(SW_WRONG_MAC);
        	
        }
        ////////////////////////////////////////////[End] security operations]///////////////////////////////////////////////////
        
        // get the credit amount
        byte creditAmount = buffer[ISO7816.OFFSET_CDATA];

        // check the credit amount
        if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }

        // credit the amount
        balance = (short) (balance + creditAmount);

    } // end of deposit method

    private void debit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        byte numBytes = (buffer[ISO7816.OFFSET_LC]);

        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if ((numBytes != 9) ) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        ////////////////////////////////////////////[Start] security operations////////////////////////////////////////////////////
        //get MAC and store it in receivedMac
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA+1) , receivedMac ,(short) 0, (short)8);    		
    	//verify MAC {CLA,INS,P1,P2,LC,DATA}
        
        sig.init(deskey, Signature.MODE_VERIFY);
        boolean isMacValid = sig.verify(buffer, (short)0, (short)(ISO7816.OFFSET_CDATA+1), receivedMac,(short)0,(short)receivedMac.length);
        
        if (!isMacValid) {
        	
        	ISOException.throwIt(SW_WRONG_MAC);
        	
        }
        ////////////////////////////////////////////[End] security operations]///////////////////////////////////////////////////
        
        
      

        // get debit amount
        byte debitAmount = buffer[ISO7816.OFFSET_CDATA];

        // check debit amount
        if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance - debitAmount) < (short) 0) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }

        balance = (short) (balance - debitAmount);

    } // end of debit method

    private void getBalance(APDU apdu) {

        byte[] buffer = apdu.getBuffer();

        // inform system that the applet has finished
        // processing the command and the system should
        // now prepare to construct a response APDU
        // which contains data field
        short le = apdu.setOutgoing();

        if (le < (2+8)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        ////////////////////////////////////////////[Start] security operations////////////////////////////////////////////////////
        //get MAC and store it in receivedMac
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA) , receivedMac ,(short) 0, (short)8);
    	//verify MAC {CLA,INS,P1,P2,LC}
        sig.init(deskey, Signature.MODE_VERIFY);
        boolean isMacValid = sig.verify(buffer, (short)0, (short)(ISO7816.OFFSET_CDATA), receivedMac,
        		(short)0,(short)receivedMac.length);
        if (!isMacValid) {
        	ISOException.throwIt(SW_WRONG_MAC);
        }
        ////////////////////////////////////////////[End] security operations]////////////////////////////////////////////////////
        // informs the CAD the actual number of bytes
        // returned
        apdu.setOutgoingLength((byte) (2+8));

        // move the balance data into the APDU buffer
        // starting at the offset 0
        buffer[0] = (byte) (balance >> 8);
        buffer[1] = (byte) (balance & 0xFF);

        ////////////////////////////////////////////[Start] security operations////////////////////////////////////////////////////
        //Calculate MAC
        
        sig.init(deskey, Signature.MODE_SIGN);
        sig.sign(buffer, (short)0,  (short) 2, generatedMac,  (short)0);
       
        
        // adding MAC to Response
        
        Util.arrayCopy(generatedMac, (short) 0 , buffer ,(short) 2, (short)8);
        
        ////////////////////////////////////////////[End] security operations]////////////////////////////////////////////////////

        // send the 2-byte balance at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short) 0, (short) (2+8));

    } // end of getBalance method

    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
      
        ////////////////////////////////////////////[Start] security operations////////////////////////////////////////////////////
        //get MAC and store it in receivedMac
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA+5) , receivedMac ,(short) 0, (short)8);//source, where start
    	//verify MAC {CLA,INS,P1,P2,LC}
        
        sig.init(deskey, Signature.MODE_VERIFY);
        boolean isMacValid = sig.verify(buffer, (short)0, (short)(ISO7816.OFFSET_CDATA+5), receivedMac,(short)0,(short)receivedMac.length);
        
        if (!isMacValid) {
        	
        	ISOException.throwIt(SW_WRONG_MAC);
        	
        }
        ////////////////////////////////////////////[End] security operations]////////////////////////////////////////////////////

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if(pin.getTriesRemaining()==0) {
        	ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        else if (pin.check(buffer, (short)ISO7816.OFFSET_CDATA,(byte)5) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
        

    } // end of validate method
} // end of class Wallet

