use Socket;
use Time::HiRes 'time';

use constant TIMEOUT=>2;

my(%F,$P,@A,@NS);
my(%RRtype,%RRcode,%Rcode,$N,$qname,$qtype,$server);
my(%P,$Z,$L,$E);

&dat;
&prm;
if ($F{h}||(!@A&&!$P)) {&hlp; exit};
&cpy if !($F{x}||$F{b});

if ($P){
  my($o,@P,$pr,$l)=(0,split //,$P);
  while ($o<=$#P){
    $pr=join '',@P[$o..$o+2];
    $l=0; $o+=3;
    while ($o<=$#P) {
      $o++,next if $P[$o]eq' ';
      if ($P[$o] ge '0' && $P[$o] le '9') {
          $l=$l*10+$P[$o]; $o++
          } else {$o++;last}
    }
    $o++ if $P[$o]eq"\xD"; $o++ if $P[$o]eq"\xA";
    prc("file",$pr,undef,@P[$o..$o+$l-1]);
    $o+=$l; #+CRLF
    $o++ if $P[$o]eq"\xD"; $o++ if $P[$o]eq"\xA";
  }
}else{
  $N=0;
  N:for $ns (@NS){
    for $pr ('udp','tcp'){
      $q=question($pr,$N++,$qname,$qtype,$F{r});
        prc($ns,$pr,undef,split //,$q);
      ($msg,$time)=get($pr,$q,$ns);
        @msg=split //,$msg;
      my %t=prc($ns,$pr,$time,@msg);
      next if !@msg;
      next if $t{Header}{TC};
      next if $t{Header}{RCODE} && $qtype==252;
      last N if @msg;
    }
  }
}

sub prc{
  my($ns,$pr,$t,@m,$ID,$QR,$RCODE)=@_;
  return unless @m;
  ($Z,$L,%P)=decode($pr,@m);
  if ($F{b}) {
    binmode(STDOUT);
    print "$pr ".@m."\n".join('',@m)."\n";
    return;
  }
  print "\nPacket $P{Header}{ID} ".($P{Header}{QR}?"received in ".rnd($t,3)." ms":"sent")." ($ns:$pr, $#m bytes) - $Rcode{$P{Header}{RCODE}}\n" if $F{s};
  print "Decode Error - $E" if $E;
  print dmp(@m) if $F{d};
  print "$L\n" if $F{l};
  print "$Z\n" if $F{z};
  if (!$P{Header}{RCODE} && !$P{Header}{TC}) {
    $mn=$ml=$mt=0;
    if($P{Header}{ANCOUNT}) {
      for (@{$P{Answer}}) { $mn=max($mn,length($_->{NAME})); $ml=max($ml,length($_->{TTL})); $mt=max($mt,length($RRcode{$_->{TYPE}}));}
      for (@{$P{Answer}}) { printf "%-${mn}s IN %-${ml}s %-${mt}s $_->{RDATA1}\n",$_->{NAME},$_->{TTL},$RRcode{$_->{TYPE}}}
    }elsif($P{Header}{NSCOUNT}){
      print "No answer section - set recurse or ask authority:\n";
      for (@{$P{Authority}}) { $mn=max($mn,length($_->{NAME})); $ml=max($ml,length($_->{TTL})); $mt=max($mt,length($RRcode{$_->{TYPE}}));}
      for (@{$P{Authority}}) { printf "%-${mn}s IN %-${ml}s %-${mt}s $_->{RDATA1}\n",$_->{NAME},$_->{TTL},$RRcode{$_->{TYPE}}}
    }
  }
  #print "\n" if !($F{s}||$F{d}||$F{z}||$F{l});
  %P;
}
sub get{
  my($t,$q,$ns)=@_;
  my $time=time;
  my($f,$timeout,$msg,$S)=('',$F{t},'');
  $sock=sockaddr_in(53,inet_aton($ns));
  if (lc $t eq 'udp'){
    socket $S, PF_INET, SOCK_DGRAM, getprotobyname('udp');
    return('',time-$time) if !send $S,$q,0,$sock;
    $msg=sr($S,1500,$timeout);
  }
  if (lc $t eq 'tcp'){
    my($b,$bn,$n,$soa)=(0,0,0,0);
    socket $S, PF_INET, SOCK_STREAM, getprotobyname('tcp');
    eval {connect $S,$sock};
    return('',time-$time) if !send $S,$q,0;
    L:while (1){
      $b=sr($S,2,$timeout)||'';
      $b.=sr($S,1,$timeout) if length $b==1;
      last if length $b<2;
      $msg.=$b;
      $n=w($b);
      last if !$n;
      $b='';
      while (length $b<$n){
        $b1=sr($S,$n-length $b,$timeout);
        last L if !length $b1;
        $b.=$b1;
      }
      #detect SOA
      (undef,undef,%p)=decode_msg(0,split //,$b);
      if ($p{Header}{ANCOUNT}){ for (@{$p{Answer}}) {$soa++ if $_->{TYPE}==6} };
      $msg.=$b;
      last L if $soa>1;
    }
  }
  close $S;
  ($msg,time-$time);

  sub sr{
    my($S,$n,$t,$f,$b)=@_;
    vec($f='',fileno($S),1)=1;
    recv $S,$b='',$n,0 if select $f,undef,undef,$t;
    return $b;
  }
}

sub dmp{
  my(@m)=@_;
  my($N,$r)=16;
  for $i (0..$#m/$N){
    $r.=sprintf("%06x  ",$i*$N);
    for (0..$N-1){
      $t=$i*$N+$_;
      $r.=" " if $_ && !($_%8);
      if ($t>$#m) {$r.='   '} else {$r.=sprintf("%02x ",ord($m[$t]))};
    }
    $r.=' ';
    for (0..$N-1){
      $t=$i*$N+$_;
      if ($t>$#m) {$r.=' '} else {$x=ord($m[$t]); $r.=($x>=7&&$x<=10||$x==13?'.':$m[$t])};
    }
    $r.="\n";
  }
  $r;
}
sub dmps{
  my($o,$s,@m)=@_;
  my($N,$t,$r)=8;
  for $i (0..$#m/$N){
    $r.=sprintf("%06x  ",$o+$i*$N);
    for (0..$N-1){
      $t=$i*$N+$_;
      if ($t>$#m) {$r.='   '} else {$r.=sprintf("%02x ",ord($m[$t]))};
    }
    $r.=' ';
    for (0..$N-1){
      $t=$i*$N+$_;
      if ($t>$#m) {$r.=' '} else {$r.=ord($m[$t])<32?'.':$m[$t]};
    }
    $r.=$i?"\n":"\t$s\n";
  }
  $r;
}

sub question{
  my $q=pack("n",$_[1]).
        header_flags(0,0,0,0,$_[4],0,0).
        pack("n4",1,0,0,0).
        name2dns($_[2])."\0".chr($_[3])."\0\1";
  (lc $_[0]=~/tcp/)?pack("n",length $q).$q:$q;
}
sub header_flags {
#   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
# |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
  if (wantarray){
    my($b)=sprintf("%.16b",$_[0]);
    return(oct("0b".substr($b,0,1)),
           oct("0b".substr($b,1,4)),
           oct("0b".substr($b,5,1)),
           oct("0b".substr($b,6,1)),
           oct("0b".substr($b,7,1)),
           oct("0b".substr($b,8,1)),
           oct("0b".substr($b,12,4)));
  }else{
    my($QR,$OPCODE,$AA,$TC,$RD,$RA,$RCODE)=@_;
    return pack("n",$QR    <<15 & 0x8000 |
                    $OPCODE<<11 & 0x7800 |
                    $AA    <<10 & 0x0400 |
                    $TC    << 9 & 0x0200 |
                    $RD    << 8 & 0x0100 |
                    $RA    << 7 & 0x0080 |
                    $RCODE      & 0x000F);
  }
}
sub decode{
  my($pr,@m)=@_;
  if (lc $pr eq 'udp'){
    return decode_msg(0,@m);
  }else{
    my($o,$cn,$n,%P,$Z,$L,%p,$z,$l)=(0,0);
    $E='';
    while ($o<$#m){
      $E='Unexpected message end',last if $o+1>$#m;
      $n=w(@m[$o..$o+1]);
        $L.=($o?"\n":'').dmps($o,'Chunk length',@m[$o..$o+1]);
        $Z.="\tTCP Chunk $cn started (length $n):\n";
      $o+=2;
      $E='Unexpected message end',last if $o+$n-1>$#m;
      ($z,$l,%p)=decode_msg($o,@m[$o..$o+$n-1]);
        $L.=$l;
        $Z.=$z;
        if (%P){
          $P{Header}{ANCOUNT}+=$p{Header}{ANCOUNT};
          $P{Header}{NSCOUNT}+=$p{Header}{NSCOUNT};
          $P{Header}{ARCOUNT}+=$p{Header}{ARCOUNT};
          $P{Answer}=[@{$P{Answer}},@{$p{Answer}}];
          $P{Authority}=[@{$P{Authority}},@{$p{Authority}}];
          $P{Additional}=[@{$P{Additional}},@{$p{Additional}}];
        }else{
          %P=%p;
        }
      $o+=$n; $cn++;
    }
    return ($Z,$L,%P);
  }
}
sub decode_msg{
  my($o,@m)=@_;
  my(%p,$z,$l,$p);
  $E='';
  # HEADER
  $E='Unexpected message end',return if $#m<11;
  $p{Header}{ID}=w(@m[0..1]);
 ($p{Header}{QR},$p{Header}{OPCODE},$p{Header}{AA},$p{Header}{TC},$p{Header}{RD},$p{Header}{RA},$p{Header}{RCODE})=header_flags(w(@m[2..3]));
  $p{Header}{QDCOUNT}=w(@m[4..5]);
  $p{Header}{ANCOUNT}=w(@m[6..7]);
  $p{Header}{NSCOUNT}=w(@m[8..9]);
  $p{Header}{ARCOUNT}=w(@m[10..11]);
  $l.="\tHEADER:\n".
      dmps($o,"ID",@m[0..1]).
      dmps($o+2,"Flags",@m[2..3]).
      dmps($o+4,"QDCOUNT",@m[4..5]).
      dmps($o+6,"ANCOUNT",@m[6..7]).
      dmps($o+8,"NSCOUNT",@m[8..9]).
      dmps($o+10,"ARCOUNT",@m[10..11]);
  ($z.=<<ZEOH)=~s/(\w+(\([^\)]*\)))/eval "$1"/eg;
\tHEADER:
Query Identifier = $p{Header}{ID}
DNS Flags:
  $p{Header}{QR}............... = sw($p{Header}{QR},Request,Response)
  .sprintf('%.4b',$p{Header}{OPCODE})........... = sw($p{Header}{OPCODE},'Standard Query','Inverse Query','Server Status Request',Reserved)
  .....$p{Header}{AA}.......... = Server sw($p{Header}{AA},'not','is') authority for domain
  ......$p{Header}{TC}......... = Message sw($p{Header}{TC},complete,truncated)
  .......$p{Header}{RD}........ = Recursive query sw($p{Header}{RD},not,'') desired
  ........$p{Header}{RA}....... = sw($p{Header}{RA},'No recursive queries on server','Recursive queries supported by server')
  .........000.... = Reserved
  ............sprintf('%.4b',$p{Header}{RCODE}) = sw($p{Header}{RCODE},'No error','Format error','Server failure','Name Error','Not Implemented',Refused,Reserved)
Question Entry Count = $p{Header}{QDCOUNT}
Answer Entry Count = $p{Header}{ANCOUNT}
Name Server Count = $p{Header}{NSCOUNT}
Additional Records Count = $p{Header}{ARCOUNT}
ZEOH
  $p=12;
  #Question
  if ($p{Header}{QDCOUNT}) {
    ($z1,$l1,$p{Question})=decode_qr($p{Header}{QDCOUNT},$o,$p,@m);
    $l.="\tQUESTION:\n$l1";
    $z.="\tQUESTION:\n$z1";
  }
  if ($p{Header}{ANCOUNT}){
    ($z1,$l1,$p{Answer})=decode_rr($p{Header}{ANCOUNT},$o,$p,@m);
    $l.="\tANSWER:\n$l1";
    $z.="\tANSWER:\n$z1";
  }
  if ($p{Header}{NSCOUNT}){
    ($z1,$l1,$p{Authority})=decode_rr($p{Header}{NSCOUNT},$o,$p,@m);
    $l.="\tAUTHORITY:\n$l1";
    $z.="\tAUTHORITY:\n$z1";
  }
  if ($p{Header}{ARCOUNT}){
    ($z1,$l1,$p{Additional})=decode_rr($p{Header}{ARCOUNT},$o,$p,@m);
    $l.="\tADDITIONAL:\n$l1";
    $z.="\tADDITIONAL:\n$z1";
  }
  ($z,$l,%p);
}
sub decode_qr{
  my($n,$o,$p,@m)=@_;
  my($np,$tp,$z,$l,$l1,@rrs,$QNAME,$name,$QTYPE,$type,$QCLASS)=$p;
  for (1..$n){
    ($QNAME,$np)=unpack_dns_name($tp=$np,@m);
      $name=dns2name($QNAME);
      $l1=dmps($o+$tp,"QNAME",@m[$tp..$np-1]);
    $QTYPE=w(@m[$np..$np+1]);
      $type=$RRcode{$QTYPE}||"UNKNOWN";
      $l1.=dmps($o+$np,"QTYPE",@m[$np..$np+1]);
      $np+=2;
    $QCLASS=w(@m[$np..$np+1]);
      $l1.=dmps($o+$np,"QCLASS",@m[$np..$np+1]);
      $np+=2;
    $l.=' 'x8 ."Question for $name of type $type\n$l1";
    $z.=<<ZEOQ;
Question $_ Name: $name
           Type: $type ($QTYPE)
ZEOQ
    $_[2]=$np;
    push @rrs,{QNAME,$name,QTYPE,$QTYPE,QCLASS,$QCLASS};
  }
  ($z,$l,[@rrs]);
}
sub decode_rr{
  my($n,$o,$p,@m)=@_;
  my($np,$tp,$z,$l,$l1,@rrs,$NAME,$name,$TYPE,$type,$CLASS,$TTL,$RDLENGTH,$RDATA,$rdata)=$p;
  for (1..$n){
    ($NAME,$np)=unpack_dns_name($tp=$np,@m);
      $name=dns2name($NAME);
      $l1=dmps($o+$tp,"NAME",@m[$tp..$np-1]);
    $TYPE=w(@m[$np..$np+1]);
      $type=$RRcode{$TYPE}||"UNKNOWN";
      $l1.=dmps($o+$np,"TYPE",@m[$np..$np+1]);
      $np+=2;
    $CLASS=w(@m[$np..$np+1]);
      $l1.=dmps($o+$np,"CLASS",@m[$np..$np+1]);
      $np+=2;
    $TTL=dw(@m[$np..$np+3]);
      $l1.=dmps($o+$np,"TTL",@m[$np..$np+3]);
      $np+=4;
    $RDLENGTH=w(@m[$np..$np+1]);
      $l1.=dmps($o+$np,"RDLENGTH",@m[$np..$np+1]);
      $np+=2;
    $RDATA=join('',@m[$np..$np+$RDLENGTH-1]);
      $l1.=dmps($o+$np,"RDATA",@m[$np..$np+$RDLENGTH-1]);
    $rdata=decode_rdata($TYPE,$RDATA,$np,@m);
    $np+=$RDLENGTH;
    $l.=' 'x8 ."$name IN $TTL $type $rdata\n$l1";
    $z.=<<ZEOR;
Resource Record $_ Name: $name
                  Type: $type ($TYPE)
                  Class: IN
                  TTL : $TTL
                  Data Length: $RDLENGTH
                  Data (decoded): $rdata
ZEOR
    $_[2]=$np;
    push @rrs,{NAME,$name,TYPE,$TYPE,CLASS,$CLASS,TTL,$TTL,RDLENGTH,$RDLENGTH,RDATA,$RDATA,RDATA1,$rdata};
  }
  ($z,$l,[@rrs]);
  
  sub decode_rdata{
    my($TYPE,$RDATA,$np,@m,$tp)=@_;
    if ($TYPE==1) {return join('.',unpack("C4",$RDATA))}
    if ($TYPE==6) {
      ($mname,$tp)=unpack_dns_name($np,@m);
      ($rname,$tp)=unpack_dns_name($tp,@m);
      $serial=dw(@m[$tp..$tp+3]); $tp+=4;
      $refresh=dw(@m[$tp..$tp+3]); $tp+=4;
      $retry=w(@m[$tp++..$tp++]);
      $expire=w(@m[$tp++..$tp++]);
      $minimum=w(@m[$tp++..$tp++]);
      return dns2name($mname)." ".dns2name($rname)." ($serial $refresh $retry $expire $minimum)";
    }
    if ($TYPE>=2&&$TYPE<=9) {return dns2name(unpack_dns_name($np,@m))}
    if ($TYPE==10) {return $RDATA}
    if ($TYPE==11) {return "data not supported"}
    if ($TYPE==12) {return dns2name(unpack_dns_name($np,@m))}
    if ($TYPE==13) {return $RDATA}
    if ($TYPE==14) {
      ($rmailbx,$tp)=unpack_dns_name($np,@m);
      ($emailbx,$tp)=unpack_dns_name($np,@m);
      return dns2name($rmailbx)." ".dns2name($emailbx);
    }
    if ($TYPE==15) {return "[".w(@m[$np,$np+1])."] ".dns2name(unpack_dns_name($np+2,@m))}
    if ($TYPE==16) {return $RDATA}
    if ($TYPE==33) {return "".w(@m[$np,$np+1])." ".w(@m[$np+2,$np+3])." ".w(@m[$np+4,$np+5])." ".dns2name(unpack_dns_name($np+6,@m))}
    return "data not supported"
  }
}
sub unpack_dns_name{
  my($p,@m)=@_;
  my($np,$name,$packed)=($p,'',0);
  while ($t=ord($m[$p])){
    if ($t>=192){
      if (!$packed) {$np++; $packed=1}
      $p=ord($m[$p+1]);
    }else{
      $name.=join('',@m[$p..$p+$t]);
      $np+=$t+1 if ($np==$p);
      $p+=$t+1;
    }
  }
  return wantarray?($name."\0",++$np):$name;
}

sub name2dns {
  my(@n)=split /\./,$_[0];
  my($t)='';
  foreach (@n) {$t.=chr(length).$_}
  return $t."\0";
}

sub dns2name {
  my($n,$t,$p)=($_[0],'',0);
  while ($p<length($n) && ($i=ord(substr($n,$p,1)))>0) {$t.=substr($n,++$p,$i).'.'; $p+=$i;}
  return $t;
}

sub sw{ $_[0]<$#_ ? $_[$_[0]+1] : $_[$#_] }
sub w { $#_==1?ord($_[0])*256+ord($_[1]):ord(substr($_[0],0,1))*256+ord(substr($_[0],1,1)) }
sub dw { ((ord($_[0])*256+ord($_[1]))*256+ord($_[2]))*256+ord($_[3]) }
sub rnd {
  my($n,$p,$m)=@_;
  $m=$n*10**$p;
  int($m)/10**$p+($m-int($m)>=0.5?10**-$p:0);
}
sub max{ $_[0]>$_[1]?$_[0]:$_[1] }

sub cpy{
  print<<EOC;
Copyright (C) 1998-2006 Suncloud.Ru
Leonid Volkanin <leonid\@volkanin.ru>

EOC
}
sub hlp{
  cpy if !$F{x};
  print<<EOH;
Usage: nszoom [-xtNrsdzlbqh] [-ffile] name|ip [type] [server]
 x   - w/o (C)
 tN  - timeout N (2 by default) sec
 r   - recurse flag
 s   - statistics
 d   - hex dump
 z   - zoom (detail)
 l   - listing
 b   - bin output
 f   - bin input (from file)
 q   - w/o q,esc,cbreak
 h   - (or ?) help only
EOH
  exit;
}
sub dat{
  %RRtype=qw(A 1 NS 2 MD 3 MF 4 CNAME 5 SOA 6 MB 7 MG 8 MR 9 NULL 10 WKS 11 PTR 12
             HINFO 13 MINFO 14 MX 15 TXT 16 SRV 33 AXFR 252 MAILB 253 MAILA 254 * 255);
  %RRcode=reverse %RRtype;
  %Rcode=(0,'No Error', 1,'Format Error', 2,'Server Failure', 3,'Name Error', 4,'Not Implemented', 5,'Refused');
}
sub prm{
  my (%x,@a);
  $F{r}=0;
  $F{t}=TIMEOUT;
  for (@ARGV){
    if (/^-/){
      s/\?/h/;
      @a=/^-([^f]*)([f])?(.*)$/i;
      $F{lc $_}=1 for split '',$a[0];
      $F{t}=0+$1 if $a[0]=~/t(\d+)[^t]*$/i;
      open F,$a[2];
      binmode F;
      $_=join '',<F>;
      close F;
      if (lc $a[1] eq 'f'){
        $P=$_;
        next;
      }
   }else{
      push @A,$_;
    }
  }

  &dns_list;
  $qname=$A[0];
  if ($qname=~/(\d+)\.(\d+)\.(\d+)\.(\d+)/) {$qname="$4.$3.$2.$1.IN-ADDR.ARPA."}
  if (defined($RRtype{uc $A[1]})){
    $qtype=$RRtype{uc $A[1]};
    @NS=$A[2] if $A[2];
  }else{
    $qtype=($qname=~/IN-ADDR.ARPA/i)?$RRtype{PTR}:$RRtype{A};
    @NS=$A[1] if $A[1];
  }
}
sub dns_list{
  ($_=`ipconfig /all`)=~/(?:DNS Servers|DNS-серверы)\D*:\s*([\d\.\s]+)/g;
  @NS=split /\s+/,$1;
  @NS='localhost' unless @NS;
}