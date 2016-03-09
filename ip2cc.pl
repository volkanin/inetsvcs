use Socket;
use Encode;
use Time::HiRes 'time';
use Term::ReadKey;

my (%F,@A);
&prm;
my (%R,%D);
&dat;
@SIG{INT,BREAK}=(sub{})x2 if $F{q};
&hlp if !@ARGV || $F{h} || $F{'?'};
&cpy if !$F{x} && @A;

my (@L,$K,@T);
for (@A){
  my ($s,@a,$a,$c);
  last if !$F{q} && ($K.&kbd)=~/q/i;
  $K='';
  @a=ddn($_);
  $s="$_ -> " if $F{v} && !@a;
  @a=unpack 'C4',inet_aton $_ if !@a;
  $a=join '.',@a;
  $s.=($L[2]=$F{v} && @a) ? $a : !@a ? ':(' : '';
  print+($L[0] && ($L[1] || $L[2]) ? "\n" : '')."$s\n" if $s;
  $L[0]=1;
  $L[1]=$L[2];
  next if !@a;
  $c=$D{$a[0]};
  if (length $c>2){
    $c=$R{$c} ? cc(toone($a,$c)) : ':(';
  }elsif ($c eq '*'){
    $c=cc(toall($a));
  }
  $c='%(' if !$c;
  print "$c\n";
  print "$D{$c}\n" if $F{v} && $D{$c};
  if ($F{v} && $F{t}){
    printf "%.2f %s (%s)\n",reverse @$_ for @T;
  }
  $#T=-1;
}
&kbd;


sub toone{
  my ($x,@a,$a)=('LACNIC');
  return whois(@_) if uc $_[1] ne $x;
  if (@a=whois($_[0],$x)){
    return @a if cc(@a);
    for (@a){
      if (/^aut-num:\s*(\S*)/i){
        $a=$1;
        last;
      }
    }
    return whois($a,$x) if $a;
  }
}
sub toall{
  my ($a,@a,$o)=@_;
  if (@a=whois($a,'ARIN')){
    for (@a){
      if (/^orgid:\s*(\S*)/i){
        $o=uc $1;
        last;
      }
    }
    if ($o){
      return if exists $R{$o} && !$R{$o};
      return @a if $o eq 'ARIN' || !exists $R{$o};
      return toone($a,$o);
    }
  }
  R3:for (qw(RIPE AFRINIC APNIC)){
    next if !(@a=whois($a,$_));
    for (@a){
      next R3 if /^inetnum:\s*(0\.){3}0\s-\s(255\.){3}255/i ||
                 /^descr:\s*various registries/i ||
                 /^descr:\s*.*?not allocated .. apnic/i ||
                 /^descr:\s*early registration addresses/i;
    }
    return @a;
  }
  toone($a,'LACNIC');
}
sub whois{
  my ($t,@a)=time;
  R1:for (0,(6)x50){
    for (1..$_*4){
      last R1 if !$F{q} && ($K.=&kbd)=~/\x1b| |q/i;
      select undef,undef,undef,0.25;
    }
    socket S,PF_INET,SOCK_STREAM,getprotobyname 'tcp';
    eval{connect S,sockaddr_in 43,inet_aton "whois.$_[1].net"};
    send S,"$_[0]\n",0;
    for (<S>){
      push @a,$_ if /\S/ && !/^[%#]/;
    }
    close S;
    last if @a;
  }
  push @T,[@_,time-$t];
  @a;
}
sub cc{
  for (@_){
    return uc $1 if /^country:\s*(..)/i;
  }
}
sub ddn{
  my @a=split /\./,shift;
  return if $#a!=3;
  for (@a){
    return if /\D/;
    $_=oct if /^0/;
    return if $_>255;
  }
  wantarray ? @a : join '.',@a;
}
sub kbd{
  my ($s,$c);
  $s.=$c while $c=ReadKey -1;
  $s;
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
Usage: ip2cc [-xvrwtqh] [-ffile] [ip|name ...]
 x - w/o (C)
 v - verbose
 r - russian
 w - windows-1251
 t - trace (if v)
 f - ip|name list \\s delim
 q - w/o q,esc,cbreak
 h - (or ?) help only
EOH
  exit;
}
sub prm{
  for (@ARGV){
    if (/^-/){
      $F{'?'}=1 if s/\?//g;
      /^-([^f]*)f?(.*)$/i;
      $F{lc $_}=1 for split '',$1;
      next if !$2;
      $_='';
      ($_=join '',<F>)=~s/^\s*// if open F,$2;
      close F;
      push @A,split /\s+/ if $_;
    }else{
      push @A,$_;
    }
  }
}
sub dat{
  %R=(IANA,0,RIPE,1,ARIN,1,APNIC,1,LACNIC,1,AFRINIC,1);
  %D=map{
    chomp;
    my @a=split /\|/;
    $a[1]=$F{w} ? $a[2] : encode 'cp866',decode 'cp1251',$a[2] if @a>2 && $F{r};
    @a[0,1];
  }<DATA>;
}
__END__
0|IANA
1|IANA
2|IANA
3|US
4|US
5|IANA
6|US
7|IANA
8|US
9|US
10|IANA
11|US
12|AT&T
13|US
14|IANA
15|US
16|US
17|US
18|US
19|US
20|US
21|US
22|US
23|IANA
24|ARIN
25|GB
26|US
27|IANA
28|US
29|US
30|US
31|IANA
32|US
33|US
34|US
35|US
36|IANA
37|IANA
38|US
39|IANA
40|US
41|AfriNIC
42|IANA
43|AU
44|US
45|US
46|IANA
47|CA
48|US
49|IANA
50|IANA
51|GB
52|US
53|DE
54|US
55|US
56|US
57|FR
58|APNIC
59|APNIC
60|APNIC
61|APNIC
62|RIPE
63|ARIN
64|ARIN
65|ARIN
66|ARIN
67|ARIN
68|ARIN
69|ARIN
70|ARIN
71|ARIN
72|ARIN
73|ARIN
74|ARIN
75|ARIN
76|ARIN
77|RIPE
78|RIPE
79|RIPE
80|RIPE
81|RIPE
82|RIPE
83|RIPE
84|RIPE
85|RIPE
86|RIPE
87|RIPE
88|RIPE
89|RIPE
90|RIPE
91|RIPE
92|RIPE
93|RIPE
94|RIPE
95|RIPE
96|ARIN
97|ARIN
98|ARIN
99|ARIN
100|IANA
101|IANA
102|IANA
103|IANA
104|IANA
105|IANA
106|IANA
107|IANA
108|IANA
109|IANA
110|IANA
111|IANA
112|IANA
113|IANA
114|APNIC
115|APNIC
116|APNIC
117|APNIC
118|APNIC
119|APNIC
120|APNIC
121|APNIC
122|APNIC
123|APNIC
124|APNIC
125|APNIC
126|APNIC
127|IANA
128|*
129|*
130|*
131|*
132|*
133|*
134|*
135|*
136|*
137|*
138|*
139|*
140|*
141|*
142|*
143|*
144|*
145|*
146|*
147|*
148|*
149|*
150|*
151|*
152|*
153|*
154|*
155|*
156|*
157|*
158|*
159|*
160|*
161|*
162|*
163|*
164|*
165|*
166|*
167|*
168|*
169|*
170|*
171|*
172|*
173|IANA
174|IANA
175|IANA
176|IANA
177|IANA
178|IANA
179|IANA
180|IANA
181|IANA
182|IANA
183|IANA
184|IANA
185|IANA
186|LACNIC
187|LACNIC
188|*
189|LACNIC
190|LACNIC
191|*
192|*
193|RIPE
194|RIPE
195|RIPE
196|AfriNIC
197|IANA
198|*
199|ARIN
200|LACNIC
201|LACNIC
202|APNIC
203|APNIC
204|ARIN
205|ARIN
206|ARIN
207|ARIN
208|ARIN
209|ARIN
210|APNIC
211|APNIC
212|RIPE
213|RIPE
214|US
215|US
216|ARIN
217|RIPE
218|APNIC
219|APNIC
220|APNIC
221|APNIC
222|APNIC
223|IANA
224|IANA
225|IANA
226|IANA
227|IANA
228|IANA
229|IANA
230|IANA
231|IANA
232|IANA
233|IANA
234|IANA
235|IANA
236|IANA
237|IANA
238|IANA
239|IANA
240|IANA
241|IANA
242|IANA
243|IANA
244|IANA
245|IANA
246|IANA
247|IANA
248|IANA
249|IANA
250|IANA
251|IANA
252|IANA
253|IANA
254|IANA
255|IANA
AC|Ascension Island|Остров Вознесения
AD|Andorra|Андорра
AE|United Arab Emirates|Объединенные Арабские Эмираты
AF|Afghanistan|Афганистан
AG|Antigua and Barbuda|Антигуа и Барбуда
AI|Anguilla|Ангилла
AL|Albania|Албания
AM|Armenia|Армения
AN|Netherlands Antilles|Антильские острова (Нидерланд.)
AO|Angola|Ангола
AQ|Antarctica|Антарктика
AR|Argentina|Аргентина
AS|American Samoa|Американские Острова Самоа
AT|Austria|Австрия
AU|Australia|Австралия
AW|Aruba|Аруба
AZ|Azerbaijan|Азербайджан
AX|Aland Islands|Аландские острова
BA|Bosnia and Herzegovina|Босния и Герцеговина
BB|Barbados|Барбадос
BD|Bangladesh|Бангладеш
BE|Belgium|Бельгия
BF|Burkina Faso|Буркина-Фасо
BG|Bulgaria|Болгария
BH|Bahrain|Бахрейн
BI|Burundi|Бурунди
BJ|Benin|Бенин
BM|Bermuda|Бермуды
BN|Brunei Darussalam|Бруней Даруссалам
BO|Bolivia|Боливия
BR|Brazil|Бразилия
BS|Bahamas|Багамы
BT|Bhutan|Бутан
BV|Bouvet Island|острова Буве
BW|Botswana|Ботсвана
BY|Belarus|Белоруссия
BZ|Belize|Белиз
CA|Canada|Канада
CC|Cocos (Keeling) Islands|Кокосовые острова
CD|Congo, The Democratic Republic of the|Демократическая республика Конго
CF|Central African Republic|Центральноафриканская Республика
CG|Congo, Republic of|Республика Конго
CH|Switzerland|Швейцария
CI|Cote d'Ivoire|Кот-д'Ивуар
CK|Cook Islands|Острова Кука
CL|Chile|Чили
CM|Cameroon|Камерун
CN|China|Китай
CO|Colombia|Колумбия
CR|Costa Rica|Коста-Рика
CS|Serbia and Montenegro|Сербия и Черногория
CU|Cuba|Куба
CV|Cape Verde|Кабо Верде
CX|Christmas Island|Остров Рождества
CY|Cyprus|Кипр
CZ|Czech Republic|Чешская Республика
DE|Germany|Германия
DJ|Djibouti|Джибути
DK|Denmark|Дания
DM|Dominica|Доминика
DO|Dominican Republic|Доминиканская республика
DZ|Algeria|Алжир
EC|Ecuador|Эквадор
EE|Estonia|Эстония
EG|Egypt|Египет
EH|Western Sahara|Западная Сахара
ER|Eritrea|Эритрея
ES|Spain|Испания
ET|Ethiopia|Эфиопия
EU|European Union|Европейский союз
FI|Finland|Финляндия
FJ|Fiji|Фиджи
FK|Falkland Islands (Malvinas)|Фолклендские острова
FM|Micronesia, Federal State of|Микронезия
FO|Faroe Islands|Острова Фарое
FR|France|Франция
GA|Gabon|Габон
GB|United Kingdom|Великобритания
GD|Grenada|Гренада
GE|Georgia|Грузия
GF|French Guiana|Гвиана (Французская)
GG|Guernsey|остров Гернси
GH|Ghana|Гана
GI|Gibraltar|Гибралтар
GL|Greenland|Гренландия
GM|Gambia|Гамбия
GN|Guinea|Гвинея
GP|Guadeloupe|Гваделупа
GQ|Equatorial Guinea|Экваториальная Гвинея
GR|Greece|Греция
GS|South Georgia and the South Sandwich Islands|Южная Георгия и Южные Сандвичевы острова
GT|Guatemala|Гватемала
GU|Guam|Гуам
GW|Guinea-Bissau|Гвинея-Биссау
GY|Guyana|Гвиана
HK|Hong Kong|Гонконг
HM|Heard and McDonald Islands|острова Херда и Макдональда
HN|Honduras|Гондурас
HR|Croatia/Hrvatska|Хорватия
HT|Haiti|Гаити
HU|Hungary|Венгрия
ID|Indonesia|Индонезия
IE|Ireland|Ирландия
IL|Israel|Израиль
IM|Isle of Man|Остров Мэн
IN|India|Индия
IO|British Indian Ocean Territory|Британская Индийская и Океанская Территория
IQ|Iraq|Ирак
IR|Iran, Islamic Republic of|Иран
IS|Iceland|Исландия
IT|Italy|Италия
JE|Jersey|Джерси
JM|Jamaica|Ямайка
JO|Jordan|Иордания
JP|Japan|Япония
KE|Kenya|Кения
KG|Kyrgyzstan|Кыргызстан
KH|Cambodia|Камбоджа
KI|Kiribati|Кирибати
KM|Comoros|Коморские острова
KN|Saint Kitts and Nevis|Сент-Китс и Невис
KP|Korea, Democratic People's Republic|Северная Корея
KR|Korea, Republic of|Южная Корея
KW|Kuwait|Кувейт
KY|Cayman Islands|Острова Кайман
KZ|Kazakhstan|Казахстан
LA|Lao People's Democratic Republic|Лаос
LB|Lebanon|Ливан
LC|Saint Lucia|Сент-Люсия
LI|Liechtenstein|Лихтенштейн
LK|Sri Lanka|Шри-Ланка
LR|Liberia|Либерия
LS|Lesotho|Лесото
LT|Lithuania|Литва
LU|Luxembourg|Люксембург
LV|Latvia|Латвия
LY|Libyan Arab Jamahiriya|Ливия
MA|Morocco|Марокко
MC|Monaco|Монако
MD|Moldova, Republic of|Молдова
MG|Madagascar|Мадагаскар
MH|Marshall Islands|Маршалловы острова
MK|Macedonia, The Former Yugoslav Republic of|Македония
ML|Mali|Мали
MM|Myanmar|Мьянма
MN|Mongolia|Монголия
MO|Macau|Макау
MP|Northern Mariana Islands|Северные Марианские острова
MQ|Martinique|Мартиника
MR|Mauritania|Мавритания
MS|Montserrat|Монтсеррат
MT|Malta|Мальта
MU|Mauritius|Маврикий
MV|Maldives|Мальдивы
MW|Malawi|Малави
MX|Mexico|Мексика
MY|Malaysia|Малайзия
MZ|Mozambique|Мозамбик
NA|Namibia|Намибия
NC|New Caledonia|Новая Каледония
NE|Niger|Нигер
NF|Norfolk Island|Остров Норфолк
NG|Nigeria|Нигерия
NI|Nicaragua|Никарагуа
NL|Netherlands|Нидерланды
NO|Norway|Норвегия
NP|Nepal|Непал
NR|Nauru|Науру
NU|Niue|Ниуэ
NZ|New Zealand|Новая Зеландия
OM|Oman|Оман
PA|Panama|Панама
PE|Peru|Перу
PF|French Polynesia|Французская Полинезия
PG|Papua New Guinea|Папуа - Новая Гвинея
PH|Philippines|Филиппины
PK|Pakistan|Пакистан
PL|Poland|Польша
PM|Saint Pierre and Miquelon|Св. Пьер и Маквелон
PN|Pitcairn Island|Остров Питкерн
PR|Puerto Rico|Пуэрто-Рико
PS|Palestinian Territories|Палестинские территории
PT|Portugal|Португалия
PW|Palau|Палау
PY|Paraguay|Парагвай
QA|Qatar|Катар
RE|Reunion Island|Остров Воссоединения
RO|Romania|Румыния
RU|Russian Federation|Российская Федерация (Россия)
RW|Rwanda|Руанда
SA|Saudi Arabia|Саудовская Аравия
SB|Solomon Islands|Соломоновы острова
SC|Seychelles|Сейшельские острова
SD|Sudan|Судан
SE|Sweden|Швеция
SG|Singapore|Сингапур
SH|Saint Helena|остров Святой Елены
SI|Slovenia|Словения
SJ|Svalbard and Jan Mayen Islands|острова Свалбард и Джен Майен
SK|Slovak Republic|Словацкая республика
SL|Sierra Leone|Сьерра-Леоне
SM|San Marino|Сан-Марино
SN|Senegal|Сенегал
SO|Somalia|Сомали
SR|Suriname|Суринам
ST|Sao Tome and Principe|Cан-Томе и Принсипи
SU||Территории бывшего СССР
SV|El Salvador|Сальвадор
SY|Syrian Arab Republic|Сирия
SZ|Swaziland|Свазиленд
TC|Turks and Caicos Islands|Острова Текс и Кайакос
TD|Chad|Чад
TF|French Southern Territories|Французские южные территории
TG|Togo|Того
TH|Thailand|Таиланд
TJ|Tajikistan|Таджикистан
TK|Tokelau|Токелау
TL|Timor-Leste|Восточный Тимор
TM|Turkmenistan|Туркмения
TN|Tunisia|Тунис
TO|Tonga|Тонга
TP|East Timor|Восточный Тимор
TR|Turkey|Турция
TT|Trinidad and Tobago|Тринидад и Тобаго
TV|Tuvalu|Тувалу
TW|Taiwan|Тайвань
TZ|Tanzania|Танзания
UA|Ukraine|Украина
UG|Uganda|Уганда
UK|United Kingdom|Великобритания
UM|United States Minor Outlying Islands|Малые Отдаленные острова
US|United States|Соединенные Штаты Америки
UY|Uruguay|Уругвай
UZ|Uzbekistan|Узбекистан
VA|Holy See (Vatican City State)|Ватикан
VC|Saint Vincent and the Grenadines|Сент-Винсент и Гренадины
VE|Venezuela|Венесуэла
VG|Virgin Islands, British|Виргинские острова (британские)
VI|Virgin Islands, U.S.|Виргинские острова (США)
VN|Vietnam|Вьетнам
VU|Vanuatu|Вануату
WF|Wallis and Futuna Islands|Острова Уоллис и Футуна
WS|Samoa|Западное Самоа
YE|Yemen|Йемен
YT|Mayotte|Майот
YU|Yugoslavia|Югославия
ZA|South Africa|Южная Африка
ZM|Zambia|Замбия
ZW|Zimbabwe|Зимбабве
