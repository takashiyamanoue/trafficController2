import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

import javax.swing.JTextArea;

//import org.jnetpcap.packet.JMemoryPacket;
//import org.jnetpcap.packet.PcapPacket;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;

import logFile.BlockedFileManager;
/*
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
*/
import pukiwikiCommunicator.ForwardInterface;
import pukiwikiCommunicator.PacketFilter;
import pukiwikiCommunicator.PacketMonitorFilter;
import pukiwikiCommunicator.ParsePacket;

public class OneSideIO implements Runnable, ForwardInterface
{
	PcapHandle pcap;
	Thread me=null;
	
	// tcpdump�ｽﾌ確�ｽF�ｽﾌフ�ｽ�ｽ�ｽ[�ｽ�ｽ
//	public JScrollPane tcpdump_log;
//	private JScrollPane scroll; //tcpdump�ｽﾌ出�ｽﾍ（ScrollPane)
		
	String line;
	String rn ="\n";
//	LogManager logManager;
	
//	Ip4 ip = new Ip4();
	IpV4Packet ipv4=null;
//	Ethernet eth = new Ethernet();
	EthernetPacket eth= null;
	MainFrame main;
	byte [] myIpAddr;
//	PacketMonitorFilter packetFilter;
//	BlockedFileManager logFileManager;
	

	/***************************************************************************
	 * Third - we must map pcap's data-link-type to jNetPcap's protocol IDs.
	 * This is needed by the scanner so that it knows what the first header in
	 * the packet is.
	 **************************************************************************/
	int id ;
	int currentHour;
    Calendar calendar=Calendar.getInstance();
    PacketFilter forwardFilter;
//    PcapIf myIf;
    PcapNetworkInterface myIf;
//    byte[] ifMac;
    ArrayList <LinkLayerAddress> ifMac;
	public OneSideIO(MainFrame m,PcapNetworkInterface pif, PcapHandle p,PacketFilter fl, byte[] ip){
		main=m;
		myIf=pif;
		try{
// 	        ifMac = myIf.getHardwareAddress();
			ifMac = myIf.getLinkLayerAddresses();
		}
		catch(Exception e){
			ifMac=null;
		}
		forwardFilter=fl;
		forwardFilter.setReturnInterface(this);
		pcap = p;
//		id= JRegistry.mapDLTToId(pcap.datalink());
		this.myIpAddr=ip;
	}
	public void setNewPcap(PcapHandle p){
		pcap = p;
//		id= JRegistry.mapDLTToId(pcap.datalink());
	}

	/* */
//	Queue<PcapPacket> queue = new ArrayBlockingQueue<PcapPacket>(100);  	
	Queue<Packet> queue = new ArrayBlockingQueue<Packet>(100);
//    public Queue<PcapPacket> getPacketQueue(){
	/**/
	public Queue<Packet> getPacketQueue(){
    	return queue;
    }
    /**/
	private class MyPacketListener implements PacketListener{
		public MyPacketListener() {
		}
		public void gotPacket(Packet packet) {
			try {
			   if(!isToBeForwarded(packet)) return;
			   queue.offer(packet);
			   if(forwardFilter!=null)
				   forwardFilter.process(packet);
			}
			catch(Exception e) {
				System.out.println("id="+id+" if="+forwardFilter.getLabel()+" OneSideIO.run.getPacket error:"+e.toString());
			}
		}
	}
	public void run(){
//		PcapPacketHandler<Queue<PcapPacket>> handler = new PcapPacketHandler<Queue<PcapPacket>>() {  
//		  public synchronized void nextPacket(PcapPacket packet, Queue<PcapPacket> queue) {  
/*
		public synchronized void nextPacket(Packet packet, Queue<Packet> queue) {
			  try{
//			  PcapPacket permanent = new PcapPacket(packet);
				  Packet permanent = new Packet(packet);
			  if(!isFromOtherIf(packet)) return;
//			  queue.offer(permanent);
			  if(forwardFilter!=null)
				  forwardFilter.process(permanent);
			  }
			  catch(Exception e){
				  System.out.println("OneSideIO.run.nextPacket error: "+e);
			  }
		  }
		} ;
		*/
		MyPacketListener mypc=new MyPacketListener();
		try{
//		 rtn=pcap.loop(-1, handler, queue);  
			pcap.loop(-1, mypc);
		}
		catch(Exception e){
			System.out.println("ioPort:"+this.forwardFilter.getLabel()+",OneSideIO.run pcap.loop error: "+e);
			pcap.close();
			System.out.println("exitting loop, please start again.");
			return;
		}
		System.out.println("exiting pcap.loop of if-"+interfaceNo);    
		pcap.close();  
	}
	/* */
    /* 
	Queue<JMemoryPacket> queue = new ArrayBlockingQueue<JMemoryPacket>(100);  	
    public Queue<JMemoryPacket> getPacketQueue(){
    	return queue;
    }
	
	public void run(){
		PcapPacketHandler<Queue<JMemoryPacket>> handler = new PcapPacketHandler<Queue<JMemoryPacket>>(){
          public void nextPacket(PcapPacket packet, Queue<JMemoryPacket> queue) {
			  byte[] jpb=new byte[2000];
			  JMemoryPacket jp =  new JMemoryPacket(jpb);
			  jp.transferFrom(packet);
			  if(!isFromOtherIf(packet)) return;

			  queue.offer(jp);
			}
		} ;
		int rtn=0; 
		try{
		 rtn=pcap.loop(-1, handler, queue);  
		}
		catch(Exception e){
			System.out.println("OneSideIO.run pcap.loop error: "+e);
			pcap.close();
			System.out.println("exitting loop, please start again.");
			return;
		}
		System.out.println("exiting pcap.loop of if-"+interfaceNo+" due to "+rtn);    
		pcap.close();  
	}
	*/
	public void start() {
		if(me==null){
			me=new Thread(this,"OneSideIO-"+this.interfaceNo);
			me.start();
		}
	}
	
	public void stop(){
		me=null;
		System.out.println("WanSideIO loop stop");
		try{
//			this.pcap.breakloop();
			this.pcap.breakLoop();
		    this.pcap.close();
		}
		catch(Exception e){
			System.out.println(e.toString());
		}
	}
    public void sendPacketPP(ParsePacket p){
    	if(p==null) return;
    	if(!p.succeeded) return;
    	if(p.packet==null) return;
//    	JMemoryPacket pp=new JMemoryPacket(p.packet);
//    	byte[] b=p.packet.getByteArray(0, 2000);
//    	byte[] b=pp.getByteArray(0, pp.getTotalSize());
//    	this.sendByte(b);
    	this.sendPcapPacket(p.packet);
	    if(logManager!=null)
		      synchronized(logManager){
//		    	  p.packet=pp;
//			          logManager.logDetail(main,p,interfaceNo);	
		    	  logManager.logDetail(main, p, interfaceNo);
		     }
    }
    /*
    public void sendPacketJM(JMemoryPacket p, ParsePacket m){
    	if(p==null) return;
    	byte[] b= p.getByteArray(0, p.getTotalSize());
    	this.sendByte(b);
    	if(m==null) return;
    	if(!m.succeeded) return;
	    if(logManager!=null)
		      synchronized(logManager){
//		    	  m.packet=pp;
		    	  logManager.logDetail(main, m, interfaceNo);
		     }    	
    }
    */
//    public void sendPacket(PcapPacket p, ParsePacket m){
    public void sendPacket(Packet p, ParsePacket m) {
    	if(p==null) return;
//    	PcapPacket pp=new PcapPacket(p);
//    	JMemoryPacket pp=new JMemoryPacket(p);
//    	byte [] b=p.getByteArray(0, p.getTotalSize());
//    	this.sendByte(b);
    	this.sendPcapPacket(p);
    	if(m==null) return;
    	if(!m.succeeded) return;
	    if(logManager!=null)
		      synchronized(logManager){
//		    	  m.packet=pp;
//			          logManager.logDetail(main,p,interfaceNo);	
		    	  logManager.logDetail(main, m, interfaceNo);
		     }    	
    }
    public void sendByte(byte[] b){
//    	ByteBuffer bb=ByteBuffer.wrap(b);
    	synchronized(pcap){
//    		if(this.pcap.sendPacket(bb)!=Pcap.OK){
//    	    	System.out.println("error @ sendPacket(PcapPacket), if="+interfaceNo);
//    	    }
    		try {
    			this.pcap.sendPacket(b);
    		}
    		catch(PcapNativeException e) {
    			System.out.println("PcapNativeException @ sendPacket(PcapPacket,if="+interfaceNo);
    		}
    		catch(NotOpenException e) {
    			System.out.println("NotOpenException @ sendPacket(PcapPacket,if="+interfaceNo);
    		}
    		catch(NullPointerException e) {
    			System.out.println("Send Null Packet @ sendPacket(PcapPacket,if="+interfaceNo);
    		}	
    	}     	
    }
//    public void sendPcapPacket(PcapPacket p){
    public void sendPcapPacket(Packet p) {
    	synchronized(pcap){
//    		if(this.pcap.sendPacket(p)!=Pcap.OK){
//    	    	System.out.println("error @ sendPacket(PcapPacket), if="+interfaceNo);
//    	    }
    		try {
    			this.pcap.sendPacket(p);
    		}
    		catch(PcapNativeException e) {
    			System.out.println("PcapNativeException @ sendPacket(PcapPacket,if="+interfaceNo);
    		}
    		catch(NotOpenException e) {
    			System.out.println("NotOpenException @ sendPacket(PcapPacket,if="+interfaceNo);
    		}
    		catch(NullPointerException e) {
    			System.out.println("Send Null Packet @ sendPacket(PcapPacket,if="+interfaceNo);
    		}
    	}     	
    }
//   public boolean isFromOtherIf(PcapPacket p){
    public boolean isToBeForwarded(Packet p) {
    	if(myIf==null) return true;
    	if(ifMac==null) return true;
//		if (p.hasHeader(eth)) {
    	if(p.contains(EthernetPacket.class)) {
//			System.out.printf("#%d: eth.src=%s\n", n, smac);
    		EthernetPacket ep=(EthernetPacket)p;
    		EthernetPacket.EthernetHeader eph=ep.getHeader();
    		MacAddress smacAddr=eph.getSrcAddr();
    		MacAddress dmacAddr=eph.getDstAddr();

	    	if(isToTheSameSideIO(smacAddr,dmacAddr)) {
	    		return false;
	    	}
		    if(!((smacAddr.toString()).equals(ifMac.toString()))){
		    	 return true;
		    }	    	
		    return false;
	     }
         return true;
    }
    public boolean isToTheSameSideIO(MacAddress smac, MacAddress dmac) {
    	Hashtable<String, MacAddrTableElement> macAddrTable=main.macAddrTable;
    	if(macAddrTable==null) return true;
    	try {
    		if(smac==null) {
    			return true;
    		}
    	String key=smac.toString();
    	MacAddrTableElement x=macAddrTable.get(key);
    	if(x==null) {
    	    x=new MacAddrTableElement();
    	    macAddrTable.put(key, x); 
    	    x.macAddress=smac;
    	    x.ioPort=this.forwardFilter.getLabel();    	    
    	}
    	synchronized(x) {
    	    x.hasAccess=true;
    	}
    	if(forwardFilter==null) {
    		return true;
    	}
		if(!(x.ioPort).equals(this.forwardFilter.getLabel())) {
			return true;
		}    	
		if(dmac==null) {
			return false;
		}
    	String key2=dmac.toString();
    	if(key2.equals("ff:ff:ff:ff:ff:ff")) {
    		return false;
    	}    	
       	MacAddrTableElement y=macAddrTable.get(key2);    
       	String destPort="";
       	if(y!=null) {
    	   destPort=y.ioPort;
       	}
    	String myPort=this.forwardFilter.getLabel();
    	if(destPort.equals(myPort)) {
    			return true;
    	}
    	}
    	catch(Exception e) {
    		System.out.println("OneSideIO.isToTheSameSideIo,if="+id+":"+forwardFilter.getLabel()+" "+e.toString());
    		Thread.dumpStack();
    	}
    	return false;
    }

	TrafficLogManager logManager;
	public void setLogManager(TrafficLogManager m){
		logManager=m;
	}
    int interfaceNo;
    public void setInterfaceNo(int i){
    	interfaceNo=i;
    }
	public byte[] getIPAddr(){
		return this.myIpAddr;
	}
//	@Override
	public void setIpMac(byte[] ip, byte[] mac) {
		// TODO Auto-generated method stub
		this.forwardFilter.setIpMac(ip,mac);
	}
	/*
	public void sendPacketJM(JMemoryPacket x, ParsePacket m) {
		// TODO Auto-generated method stub
		
	}
	public void sendPacket(PcapPacket x, ParsePacket m) {
		// TODO Auto-generated method stub
		
	}
*/
}
