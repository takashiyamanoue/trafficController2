package pukiwikiCommunicator;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.Vector;
/*
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
*/

public class PacketMonitorFilter implements FilterInterface
{
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
	PukiwikiCommunicator pukiwiki;
	public PacketMonitorFilter(PukiwikiCommunicator pw){
		filters=new Vector();
		this.pukiwiki=pw;
		if(pukiwiki!=null)
		this.pukiwiki.setMonitorPacketFilter(this);
		if(resultQueue==null){
			resultQueue=new Vector();
		}
	}
	public void addFilter(String cmd, String[] args){
		Filter f=new Filter(cmd, args);
		filters.add(f);
	}
	public Filter elementAt(int i){
		return filters.elementAt(i);
	}
	   
//	Ip4 ip = new Ip4();
//	Ethernet eth = new Ethernet();
	
//	PcapHeader hdr = new PcapHeader(JMemory.POINTER);
//	PcapHeader hdr = new PcapHeader();
//	JBuffer buf = new JBuffer(JMemory.POINTER);
//	JBuffer buf = new JBuffer(new byte[5000]);
//	Tcp tcp = new Tcp();
//	Udp udp = new Udp();
//	String sip="";
//	String dip="";
//	String smac="";
//	String dmac="";
//	String protocol="";
//	int sport=0;
//	int dport=0;
//	PcapPacket packet;
//	JMemoryPacket packet;
	ParsePacket p;
//    String etherString="";
//   String ipString="";
//    String l4String="";
//    String ptime="";
//    byte[] payload;
//    String payloadString;
//    public String exec(PcapPacket p){
//    public String exec(JMemoryPacket p){
    public String exec(ParsePacket p){
    	this.p =p;
    	/*
    	packet=p;
		ptime=""+(new Date(packet.getCaptureHeader().timestampInMillis()));
//    	ptime=(new Date()).toString();
 		long n=packet.getFrameNumber();
 		try{
		if (packet.hasHeader(eth)) {
			smac = FormatUtils.mac(eth.source());
			dmac = FormatUtils.mac(eth.destination());
//			System.out.printf("#%d: eth.src=%s\n", packet.getFrameNumber(), str);
//			System.out.printf("#%d: eth.src=%s\n", n, smac);
			etherString=smac+"->"+dmac+" ";
		}
		if (packet.hasHeader(ip)) {
			sip = FormatUtils.ip(ip.source());
			dip = FormatUtils.ip(ip.destination());
//			System.out.printf("#%d: ip.src=%s\n", packet.getFrameNumber(), str);
//			System.out.printf("#%d: ip.src=%s\n", n, sip);
			ipString=sip+"->"+dip+" ";
		}
		else{
			
		}
        if(packet.hasHeader(tcp)){
        	protocol="tcp";
        	sport=tcp.source();
        	dport=tcp.destination();
        	try{
        	payload=tcp.getPayload();
        	}
        	catch(Exception e){
        		payload=new byte[]{'e','r','r','o','r','-','g','e','t','-','p','a','y','l','o','a','d'};
        	}
			String flags="-";
			if(tcp.flags_SYN()) flags=flags+"SYN-";
			if(tcp.flags_ACK()) flags=flags+"ACK-";
			if(tcp.flags_PSH()) flags=flags+"PSH-";
			if(tcp.flags_FIN()) flags=flags+"FIN-";
			if(tcp.flags_RST()) flags=flags+"RST-";
			if(tcp.flags_CWR()) flags=flags+"CWR-";
			if(tcp.flags_URG()) flags=flags+"URG-";
        	l4String="tcp "+sport+"->"+dport+" "+flags+" "+SBUtil.showAsciiInBinary(payload);
        	payloadString=SBUtil.showAsciiInBinary(payload);
        }
        else
        if(packet.hasHeader(udp)){
        	protocol="udp";
        	sport=udp.source();
        	dport=udp.destination();
        	try{
        	payload=tcp.getPayload();
        	}
        	catch(Exception e){
        		payload=new byte[]{'e','r','r','o','r','-','g','e','t','-','p','a','y','l','o','a','d'};
        	}
        	l4String="udp "+sport+"->"+dport+" "+SBUtil.showAsciiInBinary(payload);
        	payloadString=SBUtil.showAsciiInBinary(payload);
        }
        else{
        	
        }
 		}
 		catch(Exception e){
 			return null;
 		}
 		*/
    	for(int i=0;i<filters.size();i++){
    		Filter f=filters.elementAt(i);
    		boolean rtn=execCommand(f.getCommand(),f.getArgs());
    		if(rtn) return f.getCommand()+" "+(f.getArgs())[0];
    	}
    	return null;
    }
 
    public boolean execCommand(String command, String[] args){
//        System.out.println("ex. "+command);
    	/*
        for(int i=0;i<args.length;i++){
           if(args[i]!=null) System.out.println(args[0]);
        }
        */
//        System.out.println("\n");
        if(command.equals("get ip=")){
        	boolean rtn=false;
        	String out=p.ptimes+" "+p.etherString+p.ipString+p.l4String+"\n";
//        	System.out.println("matching..."+out);
//            if(args[0].equals(sip)){            	
        	if(isMatchIpV4Address(args[0],p.sourceIpString)){
//            	pukiwiki.writeResult(out);
            	this.writeResultToBuffer(out);
            	rtn=true;
            }
//            if(args[0].equals(dip)){
        	if(isMatchIpV4Address(args[0],p.destinationIpString)){
//            	pukiwiki.writeResult(out);
            	this.writeResultToBuffer(out);
            	rtn=true;
            }
        	return rtn;
    	}
        if(command.equals("get includes ")){
        	String out=p.ptimes+" "+p.etherString+p.ipString+p.l4String+"\n";
//        	System.out.println("matching..."+out);
//            if(args[0].equals(sip)){            	
        	if(0<=p.l4String.indexOf(args[0])){
//            	pukiwiki.writeResult(out);
            	this.writeResultToBuffer(out);
            	return true;
            }
        	return false;
    	}
        if(command.equals("get startsWith ")){
        	String out=p.ptimes+" "+p.etherString+p.ipString+p.l4String+"\n";
//        	System.out.println("matching...startsWith "+payloadString+ " and "+args[0]);
//            if(args[0].equals(sip)){
        	if(args[0]==null) return false;
        	if(p.payloadString==null){
        		p.payloadString="";
        	}
        	if(p.payloadString.startsWith(args[0])){
//            	pukiwiki.writeResult(out);
            	this.writeResultToBuffer(out);
            	return true;
            }
        	return false;
    	}
        return false;
    }

    public boolean isMatchIpV4Address(String x, String y){
//		String ax[]=new String[4];
//		String ay[]=new String[4];
		StringTokenizer stx=new StringTokenizer(x,".");
		if(stx==null) return false;
		StringTokenizer sty=new StringTokenizer(y,".");
		if(sty==null) return false;
		for(int i=0;stx.hasMoreElements();i++){
			String ax="",ay="";
			try{
			   ax=stx.nextToken();
			   ay=sty.nextToken();
			}
			catch(Exception e){
				return false;
			}
			if(!(ax.equals(ay))){
				if((!ax.equals("*")) && (!ay.equals("*"))){
					return false;
				}
			}
		}
		return true;
    }
    public void clear(){
    	this.filters.removeAllElements();
    }
    Vector <String> resultQueue;
    int resultQueueMax=10;
    public void writeResultToBuffer(String x){
    	if(resultQueue==null) return;
    	resultQueue.add(x);
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
	   public void setReturnInterface(ForwardInterface f){
		   returnInterface=f;
	   }

}
