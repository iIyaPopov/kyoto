package kyoto;

public class KyotoRecord {
	
	// ################ 14 conventional features ###################
	
	// 1. The length (number of seconds) of the connection.
	private Double duration;
	
	// 2. The connection’s service type, e.g., http, telnet, etc.
	private String service;
	
	// 3. The number of data bytes sent by the source IP address.
	private Integer srcBytes;
	
	// 4. The number of data bytes sent by the destination IPaddress.
	private Integer dstBytes;
	
	/*
	 *  5. The number of connections whose source IP address and destination
	 *  IP address are the same to those of the current connection in the past 
	 *  two seconds.
	 */
	private Integer count;

	// 6. % of connections to the same service in Count feature.
	private Double sameSrvRate;
	
	// 7. % of connections that have “SYN” errors in Count feature.
	private Double serrorRate;
	
	/*
	 * 8. % of connections that have “SYN” errors in Srvcount (the number 
	 * of connections whose service type is the same to that of the current 
	 * connection in the past two seconds) feature.
	 */
	private Double srvSerrorRate;
	
	/*
	 *  9. Among the past 100 connections whose destination IPaddress is the same 
	 *  to that of the current connection, the number ofconnections whose source 
	 *  IP address is also the same to that of thecurrent connection.
	 */
	private Integer dstHostCount;

	/*
	 *  10. Among the past 100 connections whose destination IP address is the same 
	 *  to that of the current connection, the number ofconnections whose service 
	 *  type is also the same to that of the currentconnection.
	 */
	private Integer dstHostSrvCount;

	/*
	 * 11. % of connections whose source port is the same to that of the current.
	 * connection in Dst_host_count feature
	 */
	private Double dstHostSameSrcPortRate;
	
	// 12. % of connections that have “SYN” errors in Dst_host_count feature.
	private Double dstHostSerrorRate;
	
	// 13. % of connections that “SYN” errors in Dst_host_srv_count feature.
	private Double dstHostSrvSerrorRate;
	
	/*
	 * 14. The state of the connection at the time the summary was written 
	 * (which is usually when the connection terminated). The different states are 
	 * summarized in the below section.
	 */
	private String flag;

	// ################ 10 additional features ###################
	
	/*
	 * 1. Reflects whether IDS (Intrusion Detection System) triggered an alert 
	 * for the connection; ‘0’ means any alerts were not triggered,and an arabic 
	 * numeral (except ‘0’) means the different kinds of the alerts. Parenthesis 
	 * indicates the number of the same alert observed during theconnection. 
	 * We used Symantec IDS to extract this feature.
	 */
	private Integer idsDetection;
	
	/*
	 * 2. Indicates whether malware, also known as malicious software, was observed 
	 * in the connection; ‘0’ means no malware was observed, and a string indicates 
	 * the corresponding malware observed atthe connection. We used ‘clamav’ software 
	 * to detect malwares. Parenthesis indicates the number of the same malware 
	 * observed during theconnection.
	 */
	private String malwareDetection;
	
	/*
	 * 3. Means whether shellcodes and exploit codes were used in the connection 
	 * by using the dedicated software; ‘0’ means no shell-codes and exploit codes 
	 * were observed, and an arabic numeral means the different kinds of the 
	 * shellcodes or exploit codes. Parenthesis indicates the number of the same 
	 * shellcode or exploit code observed during the connection.
	 */
	private Integer ashulaDetection;
	
	/*
	 * 4. Indicates whether the session was attack or not; ‘1’ means the session 
	 * was normal, ‘-1’ means known attack was observed in the session,and ‘-2’ 
	 * means unknown attack was observed in the session.
	 */
	private Byte label;
	
	/*
	 * 5. Indicates the source IP address used in the session. Due to the security 
	 * concerns, the original IP address on IPv4 was properly sanitized to one of 
	 * the Unique Local IPv6 Unicast Addresses (private IP addresses). Also, 
	 * the same private IP addresses are only valid in the same month: if two 
	 * private IP addresses are the same within the same month, it means their 
	 * IP addresses on IPv4 were also the same, but if two private IP addresses 
	 * are the same within the different month, their IP addresses on IPv4 are 
	 * also different.
	 */
	private String srcIpAddress;
	
	// 6. Indicates the source port number used in the session.
	private Integer srcPortNumber;
	
	/*
	 * 7. Indicates the source IP address used in the session. Due to the security 
	 * concerns, the original IP address on IPv4 wasproperly sanitized to one of 
	 * the Unique Local IPv6 Unicast Addresses (private IP address). Also, the same 
	 * private IP addresses are only valid in the same month: if two private 
	 * IP addresses are the same within the same month, it means their IP addresses 
	 * on IPv4 were also the same, but if two private IP addresses are the same 
	 * within the different month, their IP addresses on IPv4 are also different.
	 */
	private String dstIpAddress;
	
	// 8. Indicates the destination port number used in the session.
	private Integer dstPortNumber;
	
	// 9. Indicates when the session was started.
	private String startTime;
	
	// 10. Indicates the protocol used by the connection.
	private String protocol;
	
	
	
}
