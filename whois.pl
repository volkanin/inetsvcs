# whois [ip|any_str [whois]]
# Max Baklanovsky <baklanovsky@mail.ru>

use Socket;
my @a=split ':',$ARGV[1] || '';
socket S,PF_INET,SOCK_STREAM,getprotobyname 'tcp';
eval{connect S,sockaddr_in $a[1] || 43,inet_aton $a[0] || 'whois.ripe.net'};
send S,($ARGV[0] || join '.',unpack 'C4',inet_aton '')."\n",0;
print while <S>;
close S;
