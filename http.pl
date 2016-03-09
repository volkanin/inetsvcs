use Socket;
use Encode;
use Time::HiRes 'time';
use Term::ReadKey;

my $NL="\r\xa";
my ($M,$P,%F,@Y,@A)=('GET',$NL);
&prm;
@SIG{INT,BREAK}=(sub{})x2 if $F{q};
&hlp if !@ARGV || $F{h} || $F{'?'};
&cpy if !$F{x} && @A;
@A=map{esc($_)}@A if $F{e};
$P=~s/($NL)?$/$NL$NL/ if $P!~/^$NL/ && $P!~/$NL$NL/;
$F{dw}=$F{d} ? 'cp866' : $F{w} ? 'cp1251' : '';
$Y[2]=3128 if $F{y} && !$Y[2];

$|=1;
binmode STDOUT;
my ($N,$K,@R,$S)=(0,'');
A:for (@A){
  my ($nl,@a,@s,@p,$t,@h,@b)=($N++ ? $NL : '');
  last if !$F{q} && ($K.&kbd)=~/q/i;
  $K='';
  if (s/^\*//){
    err("$nl:(  $_"),next if !@R;
    @a=rel($_,@R);
  }else{
    @a=url($_);
    err("$nl:(  $a[0]"),next if $a[10] && !join '',@a[1..3];
    $a[2]||=80;
    $a[3]='/' if !$a[3];
  }
  {
    if (!$a[4]){
      $a[5]=$F{y} ? $Y[1] : $a[1];
      $a[4]=inet_aton $a[5];
      err("$nl:(  $a[5]",$F{y}),next A if !$a[4];
      $a[5]=join '.',unpack 'C4',$a[4];
    }
    if (!$a[1]){
      $a[1]=!$F{y} ? $a[5] : join '.',unpack 'C4',inet_aton '';
      $a[10]=$a[1].($a[10] eq ':' ? '' : $a[10]);
    }
    $a[6]=$F{y} ? $Y[2] : $a[2];
    $a[7]=sockaddr_in $a[6],$a[4] if !$a[7];
    if (!defined $R[7] || $R[7] ne $a[7]){
      close $S if $S;
      socket $S,PF_INET,SOCK_STREAM,getprotobyname 'tcp';
      err("$nl:(  $a[5]:$a[6]",$F{y}),next A if !connect $S,$a[7];
      $s[0]=1;
    }
    @R=@a;
    vec($s[1]='',fileno($S),1)=1;
    @p="$M ".($F{y} ? ($a[11] || 'http://').$a[10] : $a[3]).' HTTP/1.'.($F{o} ? 0 : 1);
    push @p,"Host: $a[1]" if !$F{n};
    push @p,'Connection: '.($F{c} ? 'close' : 'Keep-Alive') if $F{c} || $F{k};
    push @p,'Authorization: Basic '.b64($a[8].':'.$a[9]) if $a[8] || $a[9];
    push @p,'Proxy-Authorization: Basic '.b64($Y[8].':'.$Y[9]) if $F{y} && $Y[8].$Y[9];
    push @p,$P;
    $_=join $NL,@p;
    select undef,undef,undef,0.05;
    $t=time;
    if (select(''.$s[1],undef,undef,0) || length!=send $S,$_,0){
      undef @R,redo if !$s[0];
      err("$nl%(  $a[5]:$a[6]",$F{y}),next A;
    }
  }
  print STDERR "$nl$a[5]:$a[6]\n" if $F{r} && $s[0];
  print;
  A1:while (1){
    for (1..($F{t} ? $F{t}*4 : 1)){
      last A1 if !$F{q} && ($K.=&kbd)=~/\x1b| |q/i;
      last if $s[2]=select ''.$s[1],undef,undef,!$F{t} && (exists $F{t} || !$F{l}) ? 0 : 0.25;
    }
    $_='';
    recv $S,$_,1000,0 if $s[2];
    $F{l} && !exists $F{t} && !$s[2] ? redo : last if !length;
    {
      if (!$b[0] && ($h[0].=$_)=~/^((.*?)$NL$NL)(.*)$/s){
        print $1;
        ($h[0],$_)=($2,$3);
        $h[0]='',redo if $h[0]=~/^http\/1\.[01] +100\b/i;
        push @h,hdr($h[0]) if $F{l} || $F{dw};
        $b[0]=1;
      }
    }
    if ($F{l} && defined $h[1]){
      $b[3]=($b[1]+=length)-$h[1];
      $_=substr $_,0,length()-$b[3] if $b[3]>0;
    }
    @b[1..3]=chn(@b) if $F{l} && $h[2];
    $_=encode $F{dw},decode $h[3],$_ if$ F{dw} && $h[3];
    print;
    last if $F{l} && defined $b[3] && $b[3]>=0;
  }
  printf STDERR "%.2f  %s\n",time-$t,$a[0] if $F{r};
}
close $S if $S;
&kbd;


sub hdr{
  my @a;
  for (split $NL,$_[0]){
    if (!$a[0] && !$a[1]){
      $a[0]=$1 if /^content-length\s*:\s*(\d+)/i;
      $a[1]=1 if /^transfer-encoding\s*:\s*chunked/i;
    }
    $a[2]=Encode::resolve_alias $1 if /^content-type\s*:.*?charset\s*=\s*([\S]+)/i;
  }
  @a;
}
sub chn{
  my ($n,$s)=($_[1],$_[2] ? $_[2].$_ : $_);
  if (!$n || $n!=2){
    ($n,$s)=ch1($s) if !$n;
    while ($n && $n!=2 && $n<length $s){
      $s=substr $s,$n;
      ($n,$s)=ch1($s);
    }
    ($n,$s)=($n-length $s,'') if $n && $n!=2;
  }
  ($n,$s,$n && $n==2 && $s=~/$NL$NL/ ? 0 : undef);

  sub ch1{
    my ($s,@a)=shift;
    @a=$s=~/^(([\da-f]*).*?$NL)/is ? (2+hex $2,substr $s,length $1) : (0,$s);
    $a[1]=$NL.$a[1] if $a[0]==2;
    @a;
  }
}
sub err{
  print STDERR "$_[0]\n" if $F{r};
  $_[1] ? exit : undef @R;
}
sub kbd{
  my ($s,$c);
  $s.=$c while $c=ReadKey -1;
  $s || '';
}
sub esc{
  my ($s,$e,%h,$n)=($_[0],'',map{$_,1}split '',' <>#%"{}|\^[]`');
  $e.=33>ord || 126<ord || $h{$_} ? '%'.unpack 'H2',$_ : $_ for split '',$s;
  $e;
}
sub b64{
  my ($b,@a,$s,$n)=('','A'..'Z','a'..'z',0..9,'+','/');
  for $s ($_[0]=~/(.{1,3})/sg){
    $n=0;
    $n=$n*256+$_ for unpack 'C3',"$s\0\0";
    $b.=join '',@a[($n&16515072)>>18,($n&258048)>>12];
    $b.=length $s>1 ? $a[($n&4032)>>6] : '=';
    $b.=length $s>2 ? $a[$n&63] : '=';
  }
  $b;
}
sub rel{
  my ($s,@a)=@_;
  $a[0]=$s;
  $s=~s/#.*$//s;
  $a[10]=substr $a[10],0,-length $a[3];
  $s=~/^\// ? $a[3]=$s : $a[3]=~s/[^\/]*$/$s/;
  $a[10].=$a[3];
  @a;
}
sub url{
  my @a=($_[0],('')x9,$_[0],'');
  @a[11,8,9]=($1,$2,$3) if $a[10]=~s/^(http:\/\/|)(?:([^:@]*):?(.*?)@|)//is;
  $a[10]=~s/#.*$//s;
  @a[1..3]=$a[10]=~/^([^:\/\?]*):?(\d*)(.*)/s;
  @a;
}
sub cpy{
  print<<EOC;
Copyright (C) 1998-2006 Suncloud.Ru
Max Baklanovsky <baklanovsky\@mail.ru>

EOC
}
sub hlp{
  cpy if !$F{x};
  print<<EOH;
Usage: http [-xeoncktNldwrqh] [-mmethod] [-pfile] [-yproxy] [-ffile] [url ...]
 x   - w/o (C)
 e   - esc encoding
 o   - http 1.0
 n   - w/o host
 c|k - conn close|keep-alive
 tN  - max pause N (1 w/o N) sec
 l   - rcv stop if body length
 d|w - body in cp866|cp1251
 m   - GET by default
 p   - packet tail
 y   - [user[:pass]@]host[:port]
 f   - url|*relurl list \\n delim
 r   - report to stderr
 q   - w/o q,esc,cbreak
 h   - (or ?) help only
EOH
  exit;
}
sub prm{
  my (%x,@a,@f)=qw(c k k c d w w d);
  for (@ARGV){
    if (/^-/){
      $F{'?'}=1 if s/\?//g;
      @a=/^-([^mpyf]*)([mpyf])?(.*)$/i;
      @F{$_,$x{$_} || ''}=1 for split '',lc $a[0];
      $F{t}=0+$1 if $a[0]=~/t(\d+)[^t]*$/i;
      next if !$a[1];
      if (lc $a[1] eq 'm'){
        $M=$a[2];
        next;
      }
      if (lc $a[1] eq 'y'){
        @Y=url($a[2]);
        $F{y}=1;
        next;
      }
      open F,$a[2];
      binmode F;
      @f=<F>;
      close F;
      if (lc $a[1] eq 'p'){
        $P=join '',@f;
        next;
      }
      s/^\s*//,s/\s*$// for @f;
      push @A,grep{$_}@f;
    }else{
      push @A,$_;
    }
  }
}
