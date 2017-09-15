package pukiwikiCommunicator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.Hashtable;
import java.util.Queue;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
/*
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.resolver.IpResolver;
*/
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
//import org.jnetpcap.protocol.network.Arp;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import pukiwikiCommunicator.PacketMonitorFilter.Filter;

public class PacketFilter implements FilterInterface{

public class Filter{
	String command;
	String args[];
	public Filter(String c, String[] a){
		this.command=c;
		this.args=a;
	}
	public String getCommand(){
		return command;
	}
	public String[] getArgs(){
		return args;
	}
}


private Vector <Filter> filters;
private PukiwikiCommunicator pukiwiki;
private String myName;
//private String myMac;
private byte[] myMac;
private String networkAddrStr;
private byte[] networkAddr;
private byte[] networkMask;
private byte[] routerIP;
private byte[] myIpAddr;
public PacketFilter(PukiwikiCommunicator pw,String n, String mac, byte[] na,byte[] msk, byte[] mip){
	myName=n;
//	myMac=mac;
	myMac=SBUtil.smac2byte(mac);
	filters=new Vector();
	this.pukiwiki=pw;
	if(pukiwiki!=null)
	if(resultQueue==null){
		resultQueue=new Vector();
	}
	this.nat=new Hashtable();
	networkAddr=na;
	networkMask=msk;
	networkAddrStr=SBUtil.bytes2sip(networkAddr);
	getRouter();
	myIpAddr=mip;
}
public String getLabel() {
	return myName;
}
public void addFilter(String cmd, String[] args){
	Filter f=new Filter(cmd, args);
	filters.add(f);
}
private void getRouter(){
    BufferedReader buffer = null; 
    Process result=null;
    String gateway="";
    	String osName=System.getProperty("os.name");
    	System.out.println("osName="+osName);
    	String line="";
    	if(osName.indexOf("Windows")>=0){
    		try{
    		result = Runtime.getRuntime().exec("netstat -rn");
            BufferedReader output = new BufferedReader 
                    (new InputStreamReader(result.getInputStream())); 
            line = output.readLine(); 
            while(line != null){ 
               if ( line.indexOf("0.0.0.0") >=0 ) 
                           break;               
                line = output.readLine(); 
            } 
    		}
    		catch(Exception e){
    			System.out.println("PacketFiter.getRouter windows error:"+e);
    		}
            StringTokenizer st = new StringTokenizer( line ); 
            st.nextToken(); 
            st.nextToken();
            gateway = st.nextToken();
    	}
    	else
    	if(osName.indexOf("Linux")>=0){
            try{
           result = Runtime.getRuntime().exec("route"); 
           BufferedReader output = new BufferedReader 
            (new InputStreamReader(result.getInputStream())); 
           line = output.readLine(); 
           while(line != null){ 
               if ( line.startsWith("default") == true ) 
                   break;               
               line = output.readLine(); 
           } 
           }
           catch(Exception e){
        	   System.out.println("PacketFilter.getRouter linux error:"+e);
           }
           StringTokenizer st = new StringTokenizer( line ); 
           st.nextToken(); 
           gateway = st.nextToken();
    	}
     
     
        System.out.println(gateway);
        this.routerIP=SBUtil.s2byteIp4(gateway);
/*        
        st.nextToken(); 
        st.nextToken(); 
        st.nextToken(); 
     
        adapter = st.nextToken(); 
   */  
} 
	
private byte[] getRouterIP(){
	return routerIP;
}

/*
public Filter elementAt(int i){
	return filters.elementAt(i);
}
*/
   

Hashtable <AddressPort2, AddressPort> nat;
ParsePacket pp;
String ptime="";

/* */
//Queue<PcapPacket> queue;
Queue<Packet> queue;
//public void setPacketQueue(Queue<PcapPacket> q){
public void setPacketQueue(Queue<Packet> q) {
	queue=q;
}
/* */
/* 
Queue<JMemoryPacket> queue;
public void setPacketQueue(Queue<JMemoryPacket> q){
	queue=q;
}
 */

//private ParsePacket exec(PcapPacket p){
private ParsePacket exec(Packet p) {
//private synchronized ParsePacket exec(PcapPacket p){
//private ParsePacket exec(JMemoryPacket p){
	if(myName.equals("lan2wan")){
		int a=0;
	}
	if(p==null) return null;
	pp=new ParsePacket(p);
	if(!pp.succeeded) return null;
	ptime=pp.ptimes;
//	ptime=(new Date()).toString();
//	long n=pp.packet.getFrameNumber();

	for(int i=0;i<filters.size();i++){
		Filter f=filters.elementAt(i);
		boolean rtn=execCommand(f.getCommand(),f.getArgs(), pp);
		if(rtn) {
			return null;
		}
		else{

		}
	}
	try{
		/*
   	  if(pp.packet.hasHeader(pp.arp)){
		  byte[] buf=new byte[pp.arp.getLength()];
		  pp.arp.getByteArray(0, buf);
		  */
	  if(pp.arp!=null) {
		  try {
		    byte[] buf=pp.arp.getRawData();
		    int op=buf[7];
		    if(op==2){
		      processArpReply(pp);
		    }
		  }
		  catch(Exception e) {
				System.out.println("PacketFilter.exec.arp error:"+e.toString());
				Thread.dumpStack();
				return null;			  
		  }
	  }
   	  /*
	  if(pp.packet.hasHeader(pp.ip)){
          if(isInNat(pp.ip.source(), pp.sport, pp.ip.destination(), pp.dport)){
          	return restoreNatedPacket(pp);
          }
          */
   	  if(pp.ipv4!=null) {
		  try {
      		  if(isInNat(pp.ipv4.getHeader().getSrcAddr().getAddress(),
     				     pp.sport,
   	   			         pp.ipv4.getHeader().getDstAddr().getAddress(),
   				         pp.dport)) {
   			      return restoreNatedPacket(pp);
   		      }
		  }
		  catch(Exception e) {
				System.out.println("PacketFilter.exec.ipv4 error:"+e.toString());
				Thread.dumpStack();
				return null;			  
		  }
		  
          if(isDnsAnswer(pp)){
        	  try {
    	        byte[] dnsr=getDnsAnswerAddr(pp);
//            if(isInNat(pp.ip.destination(), pp.dport, dnsr, 0 )){
    	        if(isInNat(pp.ipv4.getHeader().getDstAddr().getAddress(),
    	    		     pp.dport,
    	    		     dnsr,0)) {
        	      this.writeResultToBuffer("substitute-destination to "+bytes2sip(dnsr),pp);
    	          return setDnsReturn(pp,dnsr);
                }
    		  }
    		  catch(Exception e) {
    				System.out.println("PacketFilter.exec.isDnsAnswer error:"+e.toString());
    				Thread.dumpStack();
    				return null;			  
    		  }
    	        
          }
	  }
	}
	catch(Exception e){
		System.out.println("PacketFilter.exec error:"+e.toString());
		return null;
	}
	return pp;
}
private boolean isInNat(byte[] x, int y, byte[] u, int w){
//	String ap=SBUtil.addrPort(x,y);
//	String sp=SBUtil.addrPort(u,w);
//	System.out.println("isInNat("+ap+","+sp+")");
	int nc=nat.size();
	if(nc==0)return false;
//	String key=sp+"-"+ap;
	AddressPort2 key=new AddressPort2(new AddressPort(x,y), new AddressPort(u,w));
//	if(ap.startsWith("163.209.19.180"))
//	System.out.println("isInNat at "+myName+" key="+key);
	AddressPort rtn=nat.get(key);
	if(rtn==null) return false;
//	System.out.println("rewriting source-ip from "+key+" to "+ rtn);
	return true;
}

private boolean execCommand(String command, String[] args, ParsePacket p){
//    System.out.println("ex. "+command);
	/*
    for(int i=0;i<args.length;i++){
       if(args[i]!=null) System.out.println(args[0]);
    }
    */
//    System.out.println("\n");
    if(command.equals("drop ip=")){
    	if(SBUtil.isMatchIpV4Address(args[0],p.sourceIpString)){
        	this.writeResultToBuffer(command,p);
        	return true;
        }
    	if(SBUtil.isMatchIpV4Address(args[0],p.destinationIpString)){
        	this.writeResultToBuffer(command,p);
        	return true;
        }
    	return false;
	}
    if(command.equals("drop includes ")){
    	if(0<=(p.l4String).indexOf(args[0])){
        	this.writeResultToBuffer(command,p);
        	return true;
        }
    	else
    	    return false;
	}
    if(command.equals("drop startsWith ")){
    	if((p.payloadString).startsWith(args[0])){
        	this.writeResultToBuffer(command,p);
        	return true;
        }
    	else
//    	return p;
    		return false;
	}
    if(command.equals("return-syn-ack ip=")){
     	if(SBUtil.isMatchIpV4Address(args[0],p.destinationIpString)){
     		if(p==null) return false;
     		if(p.tcp==null) return false;
//     		if(p.packet.hasHeader(p.tcp)){
//     		    p.packet.getHeader(p.tcp);
//     		    if(p.tcp.flags_SYN() && !p.tcp.flags_ACK()){
     		if(p.tcp.getHeader().getSyn() && !(p.tcp.getHeader().getAck())) {
    		       ParsePacket pr=makeSynAckReturn(p);
    		       if(pr==null) return true;
    		       this.returnInterface.sendPacketPP(pr);
    		       this.writeResultToBuffer(command,pr);
    		       return true;
//     	        }
//     		    return false;
            }
     		return false;
     	}
//    	return p;
     	return false;
	}
    if(command.equals("forward ip=")){
    	if(SBUtil.isMatchIpV4Address(args[0],p.destinationIpString)){
    		String faddr=args[1];
    		ParsePacket pr=makeForward(p,faddr,args[2]);
            if(pr==null) return true;
    		otherIO.sendPacketPP(pr);
    		this.writeResultToBuffer(command,pr);
    		return true;
        }
    	else{
    		return false;
    	}
	}
    if(command.equals("forward sip=")){
    	if(!p.protocol.equals("tcp")) return false;
    	if(SBUtil.isMatchIpV4Address(args[0],p.sourceIpString)){
//    		if(p.tcp.destination()==80){
    		if(p==null) return false;
    		if(p.tcp==null) return false;
    		if(p.tcp.getHeader().getDstPort().valueAsInt()==80) {
    		   String faddr=args[1];
    		   ParsePacket pr=makeForward(p,faddr,args[2]);
    		   this.writeResultToBuffer(command,pr);
    		   return true;
    		}
        }
    	else{
    		return false;
    	}
	}
    if(command.equals("dns-intercept ip=")){
    	if(!p.protocol.equals("udp")) return false;
//     	int dp=p.udp.destination();
    	if(p==null) return false;
    	if(p.udp==null) return false;
    	int dp=p.udp.getHeader().getDstPort().valueAsInt();
    	if(dp==53){
    		   ParsePacket pr=makeDnsInterCeption(p,args[0],args[1]);
    		   if(pr==null) return true;
    		   otherIO.sendPacketPP(pr);
    		   this.writeResultToBuffer(command,pr);
    		   return true;
    	}
    	else{
    		return false;
    	}
	}
    return false;
}
private String bytes2sip(byte[] x){
	int ax=0;
	ax=x[0];
	if(ax<0)ax=256+ax;
	String rtn=""+ax;
	int len=x.length;
	for(int i=1;i<len;i++){
		ax=x[i];
		if(ax<0) ax=256+ax;
		rtn=rtn+"."+ax;
	}
	return rtn;
}

public void clear(){
	this.filters.removeAllElements();
	this.nat=new Hashtable();
}
Vector <String> resultQueue;
int resultQueueMax=10;
private void writeResultToBuffer(String x,ParsePacket p){
	if(p==null) return;
	String out=ptime+" "+x+" "+p.etherString+p.ipString+p.l4String+"\n";
	if(resultQueue==null) return;
	resultQueue.add(out);
	if(resultQueue.size()>resultQueueMax)
		resultQueue.remove(0);
}
public Vector<String> getResults(){
	return resultQueue;
}
boolean isInChars(char x, char[] y){
	for(int i=0;i<y.length;i++){
		if(x==y[i]) return true;
	}
	return false;
}

   ForwardInterface returnInterface;
   ForwardInterface forwardInterface;
   public void setReturnInterface(ForwardInterface f){
	   returnInterface=f;
   }
   PacketFilter anotherSideFilter;
   public void setAnotherSideFilter(PacketFilter f){
	   anotherSideFilter=f;
   }
   private ParsePacket makeSynAckReturn(ParsePacket p){
	   /*
	   Ethernet eth=new Ethernet();
	   Ip4 ip = new Ip4();
	   Tcp tcp = new Tcp();
       PcapPacket px=new PcapPacket(p.packet);
//	   JMemoryPacket px=new JMemoryPacket(p.packet);
 * 
 */
	   if(pp.eth==null) return null;
	   if(pp.ipv4==null) return null;
	   if(pp.tcp==null) return null;
	   byte[] epb=p.eth.getRawData().clone();
	   EthernetPacket epx=null;
	   EthernetPacket.Builder epxb=null;
	   IpV4Packet ipx=null;
	   IpV4Packet.Builder ipxb=null;
	   TcpPacket tcpx=null;
	   try {
	      epx=EthernetPacket.newPacket(epb, 0, epb.length);
	      epxb=epx.getBuilder();
	      byte[] ipb=p.ipv4.getRawData().clone();
	      ipx=IpV4Packet.newPacket(ipb, 0, ipb.length);
	      ipxb=ipx.getBuilder();
	      byte[] tcpb=p.tcp.getRawData().clone();
	      tcpx=TcpPacket.newPacket(tcpb, 0, tcpb.length);
	   }
	   catch(Exception e) {
		   
	   }
	   /*
	   px.getHeader(eth);
	   px.getHeader(ip);
	   px.getHeader(tcp);
	   tcp.flags_SYN(true);
	   tcp.flags_ACK(true);
	   */
	   TcpPacket.Builder tcpxb=tcpx.getBuilder();
	   tcpxb.syn(true);
	   tcpxb.ack(true);
	   /*
	   byte [] sao=ip.source();
	   byte [] dao=ip.destination();
	   */
	   byte [] sao=p.ipv4.getHeader().getSrcAddr().getAddress();
	   byte [] dao=p.ipv4.getHeader().getDstAddr().getAddress();
	   /*
	   byte [] sa=new byte[sao.length];
	   byte [] da=new byte[dao.length];
	   for(int i=0;i<sao.length;i++) sa[i]=sao[i];
	   for(int i=0;i<dao.length;i++) da[i]=dao[i];
	   */
	   byte [] sa=sao.clone();
	   byte [] da=dao.clone();
	   /*
	   int sp=tcp.source();
	   int dp=tcp.destination();
	   */
	   int sp=pp.tcp.getHeader().getSrcPort().valueAsInt();
	   int dp=pp.tcp.getHeader().getDstPort().valueAsInt();
	   /*
	   ip.source(da);
	   ip.destination(sa);
	   */
	   try {
	   ipxb.srcAddr((Inet4Address)(Inet4Address.getByAddress(da)));
	   ipxb.dstAddr((Inet4Address)(Inet4Address.getByAddress(sa)));
	   }
	   catch(Exception e) {
		   
	   }
	   /*
	   tcp.source(dp);
	   tcp.destination(sp);
	   tcp.checksum(tcp.calculateChecksum());
	   */
	   tcpxb.srcPort(TcpPort.getInstance((short)dp));
	   tcpxb.dstPort(TcpPort.getInstance((short)sp));
	   /*
	   ip.checksum(ip.calculateChecksum());
	   */
	   tcpxb.correctChecksumAtBuild(true);
	   ipxb.payloadBuilder(tcpxb);
	   ipxb.correctChecksumAtBuild(true);
	   epxb.payloadBuilder(ipxb);
	   p.packet=epxb.build();
	   p.ipv4=ipxb.build();
	   p.tcp=tcpxb.build();
	   return p;
   }
   private ParsePacket makeDnsInterCeption(ParsePacket p, String oaddr, String newAddr){
	   if(this.anotherSideFilter!=null){
		   /*
		   Ethernet eth=new Ethernet();
		   Ip4 ip = new Ip4();
		   Udp udp = new Udp();
		   PcapPacket px=new PcapPacket(p.packet);
//		   JMemoryPacket px=new JMemoryPacket(p.packet);
 * 
 */
		   if(pp.eth==null) return null;
		   if(pp.ipv4==null) return null;
		   if(pp.udp==null) return null;
//		   byte[] etb=p.eth.getRawData().clone();
//		   EthernetPacket ex=EthernetPacket.newPacket(etb, 0, etb.length);
		   /*
		   px.getHeader(eth);
		   px.getHeader(ip);
		   px.getHeader(udp);
		   */
		   
		   byte[] da=SBUtil.s2byteIp4(oaddr);
		   byte[] na=SBUtil.s2byteIp4(newAddr);
		   AddressPort a=new AddressPort(da,0);
//		   AddressPort s=new AddressPort(ip.source(),udp.source());
		   AddressPort s=new AddressPort(pp.ipv4.getHeader().getSrcAddr().getAddress(),
				                         pp.udp.getHeader().getSrcPort().valueAsInt());
		   AddressPort b=new AddressPort(na,0);
		   anotherSideFilter.setNatA(new AddressPort2(a,s), b);
		   /*
 		   udp.checksum(udp.calculateChecksum());
		   ip.checksum(ip.calculateChecksum());
		   eth.checksum(eth.calculateChecksum());
		   p.packet=px;
		   */
		   return p;
	   }
	   return null;
   }
//   final PcapPacket jp = new PcapPacket(64 * 1024); 
   private ParsePacket makeForward(ParsePacket pp, String faddr, String port){
//	   if(!(pp.packet.hasHeader(pp.ip))) return null;
	   if(!(pp.ipv4==null)) return null;
	   System.out.println("PacketFilter.makeForward faddr="+faddr+" port="+port);
	   /*
	   PcapPacket jp=new PcapPacket(pp.packet);
	   Ethernet eth=new Ethernet();
	   Ip4 ip=new Ip4();
	   Tcp tcp=new Tcp();
	   Udp udp=new Udp();
	   jp.getHeader(eth);
	   jp.getHeader(ip);
	   byte[] macO=eth.destination();
	   byte[] da=SBUtil.s2byteIp4(faddr);
	   byte[] oa=ip.destination();
	   byte[] sa=ip.source();
	   */
	   byte[] macO=pp.eth.getHeader().getDstAddr().getAddress();
	   byte[] da=SBUtil.s2byteIp4(faddr);
	   byte[] oa=pp.ipv4.getHeader().getDstAddr().getAddress();
	   byte[] sa=pp.ipv4.getHeader().getSrcAddr().getAddress();
	   int sp=0;
	   int dp=(new Integer(port)).intValue();
	   int op=0;
	   if(pp.ipv4!=null) {
	   byte[] ipb=pp.ipv4.getRawData().clone();
	   IpV4Packet newIp=null;
	   try {
	     newIp=IpV4Packet.newPacket(ipb, 0, ipb.length);
	   }
	   catch(Exception e) {
		   
	   }
	   IpV4Packet.Builder newIpb=newIp.getBuilder();
/*	   if(jp.hasHeader(tcp)){
		   jp.getHeader(tcp);
		   op=tcp.destination();
		   sp=tcp.source();
	       tcp.destination(dp);
	   }
	   */

	   if(pp.tcp!=null) {
		   byte[] tcpb=pp.tcp.getRawData().clone();
		   TcpPacket newTcp=null;
		   try {
		      newTcp=TcpPacket.newPacket(tcpb, 0, tcpb.length);
		   }
		   catch(Exception e) {
			   
		   }
		   TcpPacket.Builder newTcpb=newTcp.getBuilder();
		   op=pp.tcp.getHeader().getDstPort().valueAsInt();
		   sp=pp.tcp.getHeader().getSrcPort().valueAsInt();
		   newTcpb.dstPort(TcpPort.getInstance((short)dp))
		          .correctChecksumAtBuild(true);		   
		   newIpb.payloadBuilder(newTcpb);
	   }
	   else
		   /*
	   if(jp.hasHeader(udp)) {
		   jp.getHeader(udp);
		   op=udp.destination();
		   sp=udp.source();
	       udp.destination(dp);
	   }
	   */
	   if(pp.udp!=null) {
		   byte[] udpb=pp.udp.getRawData().clone();
		   UdpPacket newUdp=null;
		   try{
			   newUdp=UdpPacket.newPacket(udpb, 0, udpb.length);
		   }
		   catch(Exception e) {
			   
		   }
		   UdpPacket.Builder newUdpb=newUdp.getBuilder();
		   op=pp.udp.getHeader().getDstPort().valueAsInt();
		   sp=pp.udp.getHeader().getSrcPort().valueAsInt();
		   newUdpb.dstPort(UdpPort.getInstance((short)dp))
		          .correctChecksumAtBuild(true);		   	   
		   newIpb.payloadBuilder(newUdpb);
	   }
	   else{
	       return null;
	   }
//	   ip.destination(da);
	   try {
	   newIpb.dstAddr((Inet4Address)(Inet4Address.getByAddress(da)))
             .correctChecksumAtBuild(true);	   
	   }
	   catch(Exception e) {
		   
	   }
	   if(this.anotherSideFilter!=null){
		    AddressPort a=new AddressPort(da,dp);
		    AddressPort s=new AddressPort(sa,sp);
		    AddressPort b=new AddressPort(oa,op);
		    AddressPort2 key=new AddressPort2(a,s);
		    System.out.println("make forward key="+key.toString()+" info="+b.toString());
		    anotherSideFilter.setNatA(key, b);
	   }
	   byte[] macD=this.getMac(da,pp);
	   byte[] ethb=pp.eth.getRawData().clone();
	   EthernetPacket newEth=null;
	   try{
		   newEth=EthernetPacket.newPacket(ethb, 0, ethb.length);
	   }
	   catch(Exception e) {
		   
	   }
	   EthernetPacket.Builder newEthb=newEth.getBuilder();
	   if(macD==null)
//	    	eth.destination(macO);
		   newEthb.dstAddr(MacAddress.getByAddress(macO));
	   else
//	        eth.destination(macD);
		   newEthb.dstAddr(MacAddress.getByAddress(macD));
	   /*
	   if(jp.hasHeader(tcp))
   	      tcp.checksum(tcp.calculateChecksum());
	   else
	   if(jp.hasHeader(udp))
		  udp.checksum(udp.calculateChecksum()); 
   	   ip.checksum(ip.calculateChecksum());
	   eth.checksum(eth.calculateChecksum());
	   this.otherIO.sendPacket(jp,pp);
	   */
	   newEthb.payloadBuilder(newIpb);
	   this.otherIO.sendPacket(newEthb.build(),pp);
	   }
	   return null;
   }
   private ParsePacket restoreNatedPacket(ParsePacket p){
/*
	   Ethernet eth=new Ethernet();
	   Ip4 ip = new Ip4();
	   Tcp tcp = new Tcp();
	   Udp udp = new Udp();
	   PcapPacket px=new PcapPacket(p.packet);
//	   JMemoryPacket px=new JMemoryPacket(p.packet);
	   px.getHeader(eth);
	   px.getHeader(ip);
	   int dp=0;
	   if(px.hasHeader(tcp)){
		   dp=tcp.destination();
	   }
	   else
	   if(px.hasHeader(udp)){
		   dp=udp.destination();
	   }
	   */
	   int dp=p.dport;
	   byte[] pxb=p.packet.getRawData().clone();
	   EthernetPacket px=null;
	   try {
	     px=EthernetPacket.newPacket(pxb,0,pxb.length);
	   }
	   catch(Exception e) {
		   
	   }
	   /*
	   byte[] x=ip.source();
	   byte[] y=ip.destination();
	   */
	   byte[] x=p.ipv4.getHeader().getSrcAddr().getAddress();
	   byte[] y=p.ipv4.getHeader().getDstAddr().getAddress();
	   AddressPort ap=new AddressPort(x,pp.sport);
	   AddressPort sp=new AddressPort(y,dp);
	   AddressPort2 key=new AddressPort2(ap,sp);
	   AddressPort op=nat.get(key);
	   System.out.println("restoreNated key="+key.toString()+" info="+op.toString());
	   System.out.println("substitute-source "+ap.toString()+"->"+op.toString());
	   this.writeResultToBuffer("substitute-source "+ap.toString()+"->"+op.toString(),p);
	   byte[] opa=op.addr;
	   /*
	   ip.source(opa);
	   if(px.hasHeader(tcp)){
		   px.getHeader(tcp);
		   int opp=op.port;
	       tcp.source(opp);
	       tcp.checksum(tcp.calculateChecksum());
	   }
	   else
	   if(px.hasHeader(udp))
	   {
		   px.getHeader(udp);
		   int opp=op.port;
		   udp.source(opp);
		   udp.checksum(udp.calculateChecksum());
	   }
	   ip.checksum(ip.calculateChecksum());
       eth.checksum(eth.calculateChecksum());
       p.packet=px;
       */
	   TcpPacket.Builder tcpb=null;
	   UdpPacket.Builder udpb=null;
	   IpV4Packet.Builder ipb=p.ipv4.getBuilder();
	   try {
	      ipb.srcAddr((Inet4Address)(Inet4Address.getByAddress(opa))).correctChecksumAtBuild(true);	   
	   }
	   catch(Exception e) {
		   
	   }
	   if(p.tcp!=null) {  
		   tcpb=p.tcp.getBuilder();
		   tcpb.srcPort(TcpPort.getInstance((short)op.port))
		       .correctChecksumAtBuild(true);
		   p.tcp=tcpb.build();
		   ipb.payloadBuilder(tcpb);
	   }
	   else
	   if(p.udp!=null){
		   udpb=p.udp.getBuilder();
		   udpb.srcPort(UdpPort.getInstance((short)op.port)).correctChecksumAtBuild(true);
		   p.udp=udpb.build();
		   ipb.payloadBuilder(udpb);
	   }
	   ipb.correctChecksumAtBuild(true);
	   p.ipv4=ipb.build();
	   EthernetPacket.Builder ethb=p.eth.getBuilder();
	   ethb.payloadBuilder(ipb);
	   p.packet=ethb.build();
	   return p;	   
   }

//	public void setNatA(String a, String b){
   public void setNatA(AddressPort2 a, AddressPort b){
	   if(this.nat!=null){
		   int nc1=nat.size();
		   nat.put(a, b);
		   int nc2=nat.size();
	   }
	}
	private boolean isDnsAnswer(ParsePacket p){
		if(!p.protocol.equals("udp")) return false;
		int sp=pp.udp.getHeader().getSrcPort().valueAsInt();
		if(sp==53) return true;  //DNS
		return false;
	}
	private byte[] getDnsAnswerAddr(ParsePacket p){
		if(!p.protocol.equals("udp")) return null;
		int sp=p.sport;
		if(sp!=53) return null;  //DNS
		byte[] pl=p.packet.getRawData();
		int pls=pl.length;
		byte[] rtn=new byte[4];
		rtn[0]=pl[pls-4];
		rtn[1]=pl[pls-3];
		rtn[2]=pl[pls-2];
		rtn[3]=pl[pls-1];
		return rtn;
	}
	private ParsePacket setDnsReturn(ParsePacket p, byte[] ap){
		if(!p.protocol.equals("udp")) return null;
		/*
		   Ethernet eth=new Ethernet();
		   Ip4 ip = new Ip4();
		   Tcp tcp = new Tcp();
		   Udp udp = new Udp();
		   PcapPacket px=new PcapPacket(p.packet);
//		   JMemoryPacket px=new JMemoryPacket(p.packet);
 */
		   EthernetPacket eth=null;
		   IpV4Packet ip=null;
		   TcpPacket tcp=null;
		   
		   int sp=p.udp.getHeader().getSrcPort().valueAsInt();
		   if(sp!=53) return null;  //DNS
		   byte[] udpb=p.udp.getRawData().clone();
		   int pls=udpb.length;
		   udpb[pls-4]=ap[0];
		   udpb[pls-3]=ap[1];
		   udpb[pls-2]=ap[2];
		   udpb[pls-1]=ap[3];
		   UdpPacket udp=null;
		   try{
			   udp=UdpPacket.newPacket(udpb, 0, udpb.length);
		   }
		   catch(Exception e) {
			   
		   }
		   UdpPacket.Builder udpx=null;
		   IpV4Packet.Builder ipb=null;
		   EthernetPacket.Builder ethb=null;
		   try {
		      udpx=udp.getBuilder().correctChecksumAtBuild(true);
		      ipb=p.ipv4.getBuilder();
		      ipb.payloadBuilder(udpx.getPayloadBuilder())
		        .correctChecksumAtBuild(true);			   
		      ethb=p.eth.getBuilder();
			  ethb.payloadBuilder(ipb).paddingAtBuild(true);
		   }
		   catch(Exception e) {
			   
		   }

/*		
		   px.getHeader(eth);
		   px.getHeader(ip);
		   px.getHeader(udp);
		   int sp=udp.source();
		   if(sp!=53) return null;  //DNS
		   byte[] pl=udp.getPayload();
		   int pls=pl.length;
		   
		   pl[pls-4]=ap[0];
		   pl[pls-3]=ap[1];
		   pl[pls-2]=ap[2];
		   pl[pls-1]=ap[3];
		   udp.checksum(udp.calculateChecksum());
		   ip.checksum(ip.calculateChecksum());
	       eth.checksum(eth.calculateChecksum());
	       */
	       p.packet=ethb.build();
		   return p;
	}
	/*
    if(isDnsAnswer(p)){
    	byte[] dnsr=getDnsAnswerAddr();
        if(isInNat(dnsr, 0)){
    	  AddrPort ap=new AddrPort(dnsr,0);
    	  return setDnsReturn(p,ap);
      }
*/

//	public void process(PcapPacket packet){
	public void process(Packet packet) {
		   if(packet!=null){
			   try {
		      ParsePacket forwardPacket=this.exec(packet);
		      if(forwardPacket!=null){
			     if(otherIO!=null){
//				    byte[] fp=forwardPacket.getByteArray(arg0, arg1);
				    otherIO.sendPacketPP(forwardPacket);
//				    otherIO.sendPacket
			    }
		     }
			   }
			   catch(Exception e) {
				   System.out.println("PacketFilter.process, if="+getLabel()+" "+e.toString());
			   }
		   }
		
	}
	ForwardInterface otherIO;
	public void setForwardInterface(ForwardInterface fi){
		otherIO=fi;
	}
	
	Hashtable <BytesWrap, byte[]> macTable=new Hashtable();
	
	private byte[] getMac(byte[] xip,ParsePacket pp){
//		String ipa=bytes2sip(xip);
		int repTimes=0;
		byte[] xmac=null;
		if(!isInNetwork(xip,networkAddr,networkMask)){
			if(this.routerIP!=null){
				xip=routerIP;
//				return pp.eth.destination(); 
				return pp.eth.getHeader().getDstAddr().getAddress();
			}
		}
		while(xmac==null){
//		    xmac=smac2byte(macTable.get(ipa));
			xmac=macTable.get(new BytesWrap(xip));
		    if(xmac==null) {
		    	if(repTimes>5) return null;
			    sendArp(xip,pp);
			    try{
			      Thread.sleep(100);
			    }
			    catch(InterruptedException e){}
			    repTimes++;
		    }
		}
		return xmac;
	}
	private byte[] smac2byte(String xmac){
		if(xmac==null) return null;
		byte[] count=new byte[16];
		byte[] rtn;
		int c=0;
		StringTokenizer st=new StringTokenizer(xmac,".:");
		while(st.hasMoreTokens()){
			String hx=st.nextToken();
			count[c]=(byte) ((Character.digit(hx.charAt(0), 16) << 4) 
                    + Character.digit(hx.charAt(1), 16)); 

			c++;
		}
		rtn=new byte[c];
		for(int i=0;i<c;i++) rtn[i]=count[i];
		return rtn;
	}
	
	private void sendArp(byte[] xip,ParsePacket pp){
/*
		JPacket packet =  
				new JMemoryPacket(JProtocol.ETHERNET_ID,  
				      " 001801bf 6adc0025 4bb7afec 08004500 "  
				    + " 0041a983 40004006 d69ac0a8 00342f8c "  
				    + " ca30c3ef 008f2e80 11f52ea8 4b578018 "  
				    + " ffffa6ea 00000101 080a152e ef03002a "  
				    + " 2c943538 322e3430 204e4f4f 500d0a");  
				  
				Ip4 ip = packet.getHeader(new Ip4());  
				Tcp tcp = packet.getHeader(new Tcp());  
				  
				tcp.destination(80);  
				  
				ip.checksum(ip.calculateChecksum());  
				tcp.checksum(tcp.calculateChecksum());  
				packet.scan(Ethernet.ID);  
				  
				System.out.println(packet);  
				*/
		ArpPacket arp=null;
//		PcapPacket p=new PcapPacket(pp.packet);
		byte[] destMac;
		byte[] ipaddr;
		byte[] myip;
		myip=this.myIpAddr;
        if(myip==null){
        	myip=this.otherIO.getIPAddr();
        }
		if(SBUtil.isSameAddress(xip, myip)){
//			this.macTable.put(bytes2sip(xip),myMac);
			this.macTable.put(new BytesWrap(xip), myMac);
			return;
		}
		else
		if(isInNetwork(xip,networkAddr,networkMask)){
			ipaddr=xip;
		}
		else{
			ipaddr=getRouterIP();
		}
//		byte[] myMacB=smac2byte(myMac);
		destMac=smac2byte("ff:ff:ff:ff:ff:ff");
//		eth.peerPayloadTo(arp);
		byte[] arpb=new byte[46];
//		arpb[0]=0; // destination mac		destMac=smac2byte("ff:ff:ff:ff:ff:ff");
		for(int i=0;i<6; i++) arpb[i]=destMac[i];
//		arpb[6]=0; // source mac;
//		for(int i=0;i<6; i++) arpb[6+i]=myMacB[i];
		for(int i=0;i<6; i++) arpb[6+i]=myMac[i];
		arpb[12]=0x08; //arp
		arpb[13]=0x06; // 
		arpb[14]=0; arpb[15]=1; arpb[16]=0x08; arpb[17]=0x00;
		arpb[18]=6; arpb[19]=4; arpb[20]=0x00; arpb[21]=0x01;
//		for(int i=0;i<6;i++) arpb[22+i]=myMacB[i];
		for(int i=0;i<6;i++) arpb[22+i]=myMac[i];
		for(int i=0;i<4;i++) arpb[28+i]=myip[i];
		for(int i=0;i<6;i++) arpb[32+i]=destMac[i];
		for(int i=0;i<4;i++) arpb[38+i]=ipaddr[i];
		arpb[42]=0; // crc-1
		arpb[43]=0; // crc-2
		arpb[44]=0; // crc-3
		arpb[45]=0; // crc-4
		/* */
//		JMemoryPacket jpx =  new JMemoryPacket(JProtocol.ETHERNET_ID,arpb);
//		Ethernet eth=new Ethernet();
//		EthernetPacket eth=null;
//		PcapPacket jp = new PcapPacket(jpx);
//        jp.getHeader(eth);		
//        jp.transferFrom(arpb);
//		p.getHeader(eth);
//		eth.source(myMacB);
//		eth.destination(destMac);
//		jp.getHeader(arp);
		ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
	      try {
	        arpBuilder
	          .hardwareType(ArpHardwareType.ETHERNET)
	          .protocolType(EtherType.IPV4)
	          .hardwareAddrLength((byte)MacAddress.SIZE_IN_BYTES)
	          .protocolAddrLength((byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
	          .operation(ArpOperation.REQUEST)
//	          .srcHardwareAddr(SRC_MAC_ADDR)
	          .srcHardwareAddr(MacAddress.getByAddress(myMac))
//	          .srcProtocolAddr(InetAddress.getByName(strSrcIpAddress))
	          .srcProtocolAddr(InetAddress.getByAddress(myip))
	          .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
//	          .dstProtocolAddr(InetAddress.getByName(strDstIpAddress));
	          .dstProtocolAddr(InetAddress.getByAddress(ipaddr));
	      } catch (UnknownHostException e) {
	        throw new IllegalArgumentException(e);
	      }

	      EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
	      etherBuilder.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
//	                  .srcAddr(SRC_MAC_ADDR)
	      		      .srcAddr(MacAddress.getByAddress(myMac))
	                  .type(EtherType.ARP)
	                  .payloadBuilder(arpBuilder)
	                  .paddingAtBuild(true);
//        eth.checksum(eth.calculateChecksum());
		
//        ParsePacket pr=new ParsePacket(new PcapPacket(eth));
        /* */
//		pp.packet=new PcapPacket(arpb);
//		pp.packet.getHeader(pp.eth);
//		pp.eth.checksum(pp.eth.calculateChecksum());
//        this.otherIO.sendPacket(pr);
//        jp.scan(Ethernet.ID);
//        PcapPacket px=new PcapPacket(jp);
//        px.scan(Ethernet.ID);
	      Packet p = etherBuilder.build();
        this.otherIO.sendPacket(p,null);
//        this.otherIO.sendPacket(px, null);
	}
	private boolean isInNetwork(byte[] h, byte[] na, byte[] mask){
		if(h==null) return false;
		if(na==null) return false;
		if(mask==null) return false;
		for(int i=0;i<h.length;i++){
			byte bi= (byte)(h[i] & mask[i]);
			if(bi!=na[i]) return false;
		}
		return true;
	}
	public void setIpMac(byte[] ip, byte[] mac){
//		this.macTable.put(SBUtil.bytes2sip(ip),SBUtil.bytes2smac(mac));
		this.macTable.put(new BytesWrap(ip), mac);
	}
	
	public void processArpReply(ParsePacket p){
		   byte[] arpb=new byte[p.arp.getRawData().length];
		ArpPacket arpPacket= null;
		try{
			arpPacket=ArpPacket.newPacket(arpb, 0, arpb.length);
		}
		catch(Exception e) {
			
		}
//		   p.arp.getByteArray(0,arpb);
		   byte[] smac=new byte[6];
		   byte[] dmac=new byte[6];
		   byte[] sip=new byte[4];
		   byte[] dip=new byte[4];
		   for(int i=0;i<6;i++) smac[i]=arpb[8+i];
		   for(int i=0;i<4;i++) sip[i]=arpb[14+i];
		   for(int i=0;i<6;i++) dmac[i]=arpb[18+i];
		   for(int i=0;i<4;i++) dip[i]=arpb[24+i];
//		   String sips=SBUtil.bytes2sip(sip); String smacs=SBUtil.bytes2smac(smac);
//		   String dips=SBUtil.bytes2sip(dip); String dmacs=SBUtil.bytes2smac(dmac);
//		   System.out.println("arp reply sips="+sips+",ssmacs="+smacs+",dips="+dips+",dmacs="+dmacs);
//		   this.macTable.put(sips, smacs);
		   this.macTable.put(new BytesWrap(sip), smac);
//		   this.macTable.put(dips, dmacs);
		   this.macTable.put(new BytesWrap(dip), dmac);
		   this.otherIO.setIpMac(dip, dmac);
		   this.otherIO.setIpMac(sip, smac);		
	}
}