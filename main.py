
import sys
import base64
import marshal
import zlib


try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ModuleNotFoundError:
    print("[FATAL] Missing dependency: pycryptodome")
    print("Install with: python -m pip install pycryptodome")
    sys.exit(1)


EXPECTED_PY = (3, 13)

if sys.version_info[:2] != EXPECTED_PY:
    print("[FATAL] Unsupported Python version")
    print(f"Expected: {EXPECTED_PY[0]}.{EXPECTED_PY[1]}")
    print(f"Found:    {sys.version_info[0]}.{sys.version_info[1]}")
    sys.exit(1)

def _xor(parts):
    from functools import reduce
    return reduce(lambda a,b: bytes(x^y for x,y in zip(a,b)), parts)

_KEY = _xor([b'f-\xa0`\xce\xac]\xd3\xa5i{\xcd\x9e\xf94?\xccA\xb3\x1f\xae\x90\x93J]\xdc\x05\xad#\x1b\xde\xe0', b"\xd8\x06vE\xd3g\xa3\xda\x90-\x07t\xae9n\xdf\xd7?\x02\x8b\xb4\xde'\x7f\xc6\x85\xe6\x80\xe6\x80\x9f\xbc", b'\xe8:\x9c/MF\x9c\xce\xa5\xf7D\xc6E\x97Z\r\xdf\x136[#!J\x00o\xeec\x13\x8f\x84\x81='])
_IV  = _xor([b'\xcauDe\x0b=\xc0\x14Q=5\x82\x8eF\x19\xc6', b')+q\xf8\xe5#)\xb8`\xd9v\x07\xc0V\xe2-'])

def _decrypt_str(d):
    iv, p = d[:16], d[16:]
    return unpad(AES.new(_KEY, AES.MODE_CBC, iv).decrypt(p), 16).decode("utf-8", "ignore")

def _decrypt_bytes(d):
    iv, p = d[:16], d[16:]
    return unpad(AES.new(_KEY, AES.MODE_CBC, iv).decrypt(p), 16)

_enc = base64.b85decode('l?UP?z+^42ql+<65fB*6<@D^{HPK`$)NbDkH`39ZGQvl*rQBe!YmW2o@;F~;b(nd|bsl^yssWr46yFnYt^sl5WY&r>L0A|b4Te0aqX|udUF487#-hZXg@WlHW!kt4pC8U=L;6a`)RNd_gdw{}`tgsQ<oEgAko=(K=MToGksx$$%zFl`T8{rV=1WKKGCv0+d|+Fer+L#XKn(_m`anMc%iAKrswb2pIb~73;u9-zS^FnsG*E%7*HtbKMMwnG)&;m^NCXJSL$r}z`KM>6Jz~;Jo@o|gAqDD#*Eg0lv4yq5XSpZQrOGofFP$57;*2ZTkX(wQq|v?|rBxzc%jP4k#PK=+7ll$rrGwB&esa^gE&xlBP(D!dfVtm6ucAN&0(<NKatmfPZ2nXyM<D7>-==c~=({y0cdSd-z@wG>4B{7~(o|@Jlm`M7`}8lPvuyp8xRe>&gbH%PC*;_AA!B_`PC%8BNrtih2F@To0`*kFj?{%FN?{^oFG)pk>j6s%EkV5~TeA}OPHp4(;X1eHv%sxo2wSq~o^nTCSos2|taB`e7UoWG=#x)Z(lmhXnan-B1v@viC#H{$Ikb_S`o4EM3e~InWZwW7H&P_u5UAu8j1W3#B|w6F0oO=I5=PSp+8WSCxP>mfC-a=!mQL6v$J^X*F8>!S+z~gzKpUxzKW{5`jb6E+OI@n-%ajNTtP}ghY^5aF2*e}g`H}6+pf}UQ1N=HVq24t!^h`I2N&FcL`h*|i!;qy&eWoiwKDv=zK~9J4E=C9*CB_XkT9V$&lN#)`K&gBo%5yO*IT+g$w9{!{sk}myEtep;CES06>_n??EXo650WN;dX<dUYbl*YV`3s;RA`zga8><iVw$29G+p$$vk$2KSP!vh%a8j*W2Z34q<&^ItuO+{&`!qO=1z*zgb<>pxm-GKkGY!{=RB(0o7av^6=r_%q17|gk=ln6uF6K|f?I#i8$cd<BC?>V7s4koZUuK_cbA_qv1ofJk6dexQbiTo;T%1x=;{~Q?gbS@r$7nc}k@|L&ePpuFTfgS5TLO=|m5ghE%E_%`fI7>POPMV;o*M9XGU@1;)1-TOYbu$dB)Jl!PhoHTmvnL?A)kJ04!ILKDifu-c^AT+Bm<ELa!9Cwk`@82N-4vghsId?haq%0u5wNgWcdPI9{FIo`0WUB{+(OmWra8d{z7MF@`&#{E-J#A9$0R4reRx?BGgnT93AZ;sv-&M8Wf}xp$cF!tU^V4AB=jc2!b&GUZy^3(un(xAq<0xCLWK>OJ4*(hEfPOxp)IuhI?qBLAx4FB{}J@pwl#=@eYGI5Ir<Tr&;lHK=8SrJTVLjUAU#MMIHjB8pXx!Zg)4EgVX`$gEcgH&^qc0Wc|X5#}4@q8*;ZFp~(JJG+io(izr~eprMv>qCo22v@fU-Z!QY~E)6r%E+p}S+Y)ark^a%s*jBMnsY2R8h&ilMf~DNugAD9axV#Wx;dGuJ@3elJ|Fu51BY#Z2mf6>gPWm2hwGswP8clYZ^U51Z|FWyL+2kYG<+e=%M<^=7EQ8y9b08#g^$v|0S&g^DWlC6WR8cE9aKxvEKewXrts%jyt!=L)9C)PXh&hZi0Bys2^N;4>*2Q4M_7(e2vi5%caU|**BfO<h?lH)qbT3$fkQ6vE<-|z$^h#*U4r<&dLq@gkClQHj+Zab-&7fI1+HFm%l@Jaqt)d5vuk4(wbsWk8)wF<tm-qWZS+O}yM0Fww!o4V#&_n}e_1}AMRQ2nx7i&)N^e%MSaRj`=xnBqa9I8^NJ?SE(l}*btvH{tfV!m(SMQICl8WW}o_j)|}Z0LIAz~vfZruV4s*?4}00*9&*lnYw{v_@jMe1il)?B^<I`t9WIj~)gDoE?G!_qhQ>d%Ct!jl*Ha9Y-)6b}o_B&7K(gKGQjkSuSnxd-kbknkP#1KubOUa?*!9FXl_{Qy23DZN|lOwjgRe%}Zmi#U!TlG^Jm|C-pv%W16Z5PCkdjO`a0gTcJej;$|R{PIhY|BrO%`2*U{{t|MF>w_*3!w$}h{%R!8W;}D?Et3?#0Wq>DfLZ$pOyB1=Johhl6h>~AiWv|<?_>2?1ULzts*e5<roPV_fFjjQem@=g`%EphSpQ(3lC?M(|lPiWIr|b)Z+V&qlY~7sJU7)jz3fdK0RWBFS^(N)_$8FYZjlk{@jP4bLCNgkIh=`}((Q<yH5@$G#x~QMHw)V!r@HyATQci#>pCT&vf)l`vf7?&<Rt?11D7T|2l#q5UbZjLNb0$LM=n}A)Kdd~fqOolcL;IVJe8x+V!h9{ozFLT;SjAfF=|AFW#I7hH0|3beE|-2jsIDtdgEsb&qvn*P#`qaA9s;z&UM=xd>JwhEgXHY8;3Y?kvz#hgy~97GQ4-{=1kv!F3lolt7r(e)!AHx-L<ZWa@c`6vRYIqisa8DjT2x{Gb28j>m=`%y4gvD^pOz|Q^cDhDA6$>d;UJ#Q8#4T;vc#*xYz#J;*`D}08Kxy>3lNn*Zd0oWGNo&e%$NbH7ZwuCwk%3VY5aYP7?PPXqHmq;uO*D2%UxondZ077?EF1Q{aUk^3bM=|mHZOhmwfBr*2J<-6uQY(V|EDOM}l(J1w%o@?^b^0R+TXUJ|3`K>CD}?aak2?X+tdwB(aYK3LR4{k=vE^aZp!@&~3n;AiF#YGjfd34A3Ddg$WZA#R1*&5%b;ifav8;;f046s|XFXK*vbaE|r>4e<i~DX5+}QW8)A;o_r>4qO3TzwW9}2OXoKgOkIwacvG!2pyOQn#g^k6uui&=E2+sKN`=eO1h8dtMe@5g4{9^DSn%oHMBMh#Nb0$PyX!I%AbII|sc|K##h7D%vuNm9;kIKB-3AjO+*u&o{B|D%qRy!t)(mV6TRSqLksTAPjRE4}q6XJBj!FU>dIK_IbMsas2tN1r?jhC8l(s*_Ce@(K;Pq?{F0BeW1Cak93W22qp33S6jTBE(Ruk!Mp~|y>3q^2iYoWht^umET34iE+E^aMxj#~PxxSN86E)2$D;QWX%JbQbLD=q}}#sG0T7Xn812yNP6ko^FcxPSe2n&7I06f4uUw>AB>$7s$R4$OnqT|T1yJ~-8sb;xilW;8SHKEkV*m1(<C@MkGqNbLmv^(a<JdEaORM<kSRA8&!{`uXiUlg^l1dL*X`WnBI%9HClgcV9i2l+6~#Z105e7nwfR5W<o4gFB~AK;_%8{><sjiB>nG#W8)T?uw#Up+G<IxLsG@vT#KA7yqBh2p-f)L@yEyJ0SluJGoiZ7s4y8O$I^@+)^(z)S63t?oROIqfKIcl^d5gjet%GfmDA;4MnZ&$@m*jYEXOGhT0r%xf=e>+n{;t*Pq^ha5jq`6as4TqLvWd{y;Hak))Kva<i;fWnbRV&v!yw=tf*pG6{$$e;`zT9({=oQ;l{Pg;?dzG@4ii-{f}8e|>qKuHJDt3Qq>R;j>;1uvEaFkRA!JSC<i8g#~QBe#M+1!QBL2(ugztW>M?DCs?1DsnYU7b^dQmoRY219!Er9bHOLkOWXa<8z`Ie{^F`q&Z(g5G(fKe(V5BH4~+*9SGkESMv#;_3`HQ`T-~DhchnP2frM>cfq4Jc$!V9`<|Cs35e42azu$wR$2A0fxFSrAY=JTFCd?SyK&O+M2u);!4|F64t;!WM4eK2<jEn<*SyBTllp4*tk-w~r8VNb!!`b`4zJsbVnx$Z9^1qmXa3%bdmvn)*q+M~vY;#@i05u+aJ%xq&vXk#U+_!Up*5Brx=!Z5b2Rz$Giu3EkD1L+l^SDQDSQRzsm|98v%QKo9I5n8$I&?i!NnLYK46qadye<D1yh+6NA1_tOQ)gwC<w77r+^zR;_#a!Q7RJyHzI>Xd@nfhv`TRA*Yu%mjAPB!V*c;x0R#&kGkxI7CY?*98YCLvhOLvSr=f=I0Q~C}R^foio-_Y1o4_(5xt+RxjmF1$R=mTjr;N~TQngqX}CMRfb9$We@!i19+TvD4a#Ulm7%o~QC@-~=m1H`R_17`l$do22i+)%^5Qk*-i9caydl(aYNl5yM|_usQ!grVduP^*u5uKA}P`VOO6b$OAEjJ(LnISBT)SHmMJMfj8pw6dLhtU`O*S{qR#Z&0RSBsjuOFtctoaVAGUJnD|AUbo=tkbNF74xIRQFx(FmysNwTo0OR{z1>rl5@5kRgC)f@YTjc^RC4u9egLh_SMK`+wIJo?UY+nCOe2}7!@;nO78aJrBRS_f`Q6x<mB~Jwb2>9<Mkyj$5W;H7Y;$y0yiO5%PsOO92hPwqlGrb=qUEWt?;+3CPPOs1v>6!FvFUCcd+j;vKi0A4DUP2Sl`ZC|(?Xq+-N?qDU&vTOtKA+&Nu|aWsJf?CwyCuod0ry7c%J@aZ?|4TdruRyM#QY~y5kH0uF+LK0|b<tv364BKv9u7R9@U(l9VmxDXi966VtRGGlTBffiej|C5?vX%LX31wiDmQLP{xf?Wi14#Y*pAyp1R*eV7ccgE7db_6SYB|6{sQ0HoEDGE^Ak!R06EgI?;yTj{WMZQUAR0|8?>%V2d7SnJk%kx>SYV0I9{M7UdWGx4zjVQt%b3UxtHQKPu8R>2eyO7Y1nW{`z&075(MMN&9;?o;dXYxty=TCM{mHW!Ajc!E9Zzo-LRd-np{N+GIVW)@eV3_YD)fLswT-*D(fCd<C4!=k>E`bQPxARM>oyItDq3-ra$`LQF%JtlC&(8#IYe7N{@Q>9MY5yI`ueh0-at}Y)=!)H>s=Ktp*^b4WQo`z0xkM>>mYi~A+^$AzmikkKk2wJX6{Z|1Y>Jwx5ZiU4^%JeUvs6$x4WAee2C?B>M@XUCaO{<K3keYaqLcR9H(`p9~zKqr-BD~6Gn0nE5gE668Lt+(yJT@H4U%bX?(wS%u@%8SdtL0;8U^T4IBdW}+-z2fYk+t`>ciZ=j(QpWa5un@!?Ws3rqwcKj@OJTce)(s$fs^A?rR-8mF!w19iCmUS<n&xm|9p%_jO({`5QjeQKMj`*o5*z|)z{}YlJCME_2~OTs^X_;+9$^G+AA#{N`ig<b(YQw6C0?*FTw~hSBQAT?J;>L)?3lE1^?%=6;>a-pCtqSnl|VvkicrvoQb%0s~G?OX0(7_G#;gK8ugkd9(nEfeOA;AEASp)eDN7pUZXBJ*jZQvQF6OxB_vn)N8Hc{I4Gvhtq|<hg@t6CK$}Yob(P8)^PiD!U=mrP((=qNGdS>^*=MrTl)N7$zJ4C*+pT4CAjPb5f*?UenRpa@^wF1pbJSbHYYVGKP79%#kgHc8LK!SLo(LL`X$nW~_SyJV^cPHy>INOXy|>|uvNmeFX$JX%2w~O&_^&co(i*nLuL`M}RNB&!0K+QNcSP^bmuyy%5TuE}v84WUcep+OAnZtf1vboOLVzhV{wx408B={C;u&g~JV#8NhJ|T!1u%i&a08|)A(rNuiQr(I5(#9eqr;9ELTw*r+H6mQIP+QQhR8I<FlTdo%nm5B9O?M&xV73?sJ{ZZuyMd!RVXQUWTs35?4>!4Z4u=9(L9N4{d#>Lm)Zd>D|}8;2W#!^?x%r38TJ$loS?8#jBC8vYT{7w<eioL-)l^YGqRynW+tR4AjTAD3zi^n-SXzBaYcZiP{2e&y!SmBoLG~6s+|6peSIWv`)odSRuw^@(jx4%a;t&aNnXPhNGK$^_>ZmZYTv7i3N~UrcA`8!)<?!`Pi8YE<C{bPZ@b*sl@`yDef%z@Ng};{Z)9FcV*lKr1pC?AkhQ_#EntDm#TFiu=7}PdtZHZKQyV~?4aCIOd#cSgf~B5>A(1ZjBH?ckZ(>KKi#_y{yazyxW*MPE5KZU@Ek+E<w%J}a7wG^n_Dvdx%i#yOhdbzMp=tuO0ALDiRl#yvF9+Z1JUs7C=y>Kq<)nXWFbk!a@fLasnP*wW3>mW|(o5x}YvF64avOjBBNIgNC6i8ADpq2CNxuAts#JQfGJ^)J#YR72deF*5di$5sWeG+ISI9JsQbtH~^vmDnGA_baRH?B!f;2YJVMa}_Q5F}0q_L(2MSpHmvP)NPjgBib0AjC$Z(&#{e6opJyG?=3@@0jQQHUyUIRrqPhNcVclE<>MtIT&G#)P`35|H+9h>tw_6-@*#1QHBH1ziJd*eL1Y@l^{VRP_0Q7T-8VXW#^lJz})W7t@$kP{MY=CYO3xnZC&)y)ZF|zH?lb<WdMHFs;6`lXbkst2+RG+72_6-|_ce{bCA8Q(pY8KoQ0xWiwV;?Rk(OU-onAv`GOO`GuMSy+(|U6M1}WvwHC2EJpp$L8i-<1uI8VEZH%E59ppz-QiIHOZYe$N>9xT;W(bOgq*Vu<Qb7><=<qoe9X>CpfM6_2gg$>yd{wn<9&xU;a4bsnknRDOcLyYUbv_Bd}vg|&Ju7Z{-Y7FvG?AMo3_8w5F2<4Ic<#l5UPIfZSnXf$(6OI<X4*kmI?w*4eOug(tuM%TJe7~^a-2#^5}YSv4db<Eiuf5q3%f@(l(F(x*}54OSqe@qfV#t07%f7{A%XF&m}I5s%47=vPglEusI8G%`do?=)^d^1xM-6;#I*FWg(_r0Xi2)yrpZ3A+M`_nWIr6_`nkaP>9jFfN#&V0e9#MvvXXTh1KMNY4VDO%?gBUdrl%D-=1o(P?=cZckl1xyhzUz=FiSVTCuQEv=~U!f%{}&Zu5O)DOodc_{y^l&I^FdYpUI^Bi*3h-l;m6o;!(zH*4}lOm<PKKQ{kA3A1ALN%d2@R><o;f%R($A3Bl#g0s>p)S`%2K%K_%+o@+{BT7u&Xd79gJ0R%>P82e;vJmFnHUy0PP!x(0owwJ>A*-sKmD_}PmUq(6{Dhj7J?0Lf#VxU?A`RB`NaHS(ux-1(FtLxVAky&yq2xhuywRo25fTY%7I*%5-ar_OZI?Vb>i&S#vrL1Wg05Fy6~u0$C<<{G6Uxb~*@OM;F_4%=cqg_n?UXR3mKyl&2BN2sb{nGPqyKbO3r(-43R-MxMP=R)Un7^n0#1_~&R@>1{-HzM9ORnrC@FOzh&RZDE?I)p{X1#+Vq_DtrhjttMa3q!qn0l`R_WMkH%?i!SzHK>oIEP_*5H!dp&)it$ayU0gbWpU@^<R*XqlhM-<bAc&tQ`2wud}by8=#ltp#v9_4n-IwKZgz=n;-xn88>4<qkspLSof6<RhqiZzkR$m`#||uv_!FB)b6w1E9o^7ll!{3c4H+FdLz~06PMd?eM8)rv(S!*iU+Uz`0mXtN_?QGalx0c_J-=rKhcYO3w~;fiPHB)VYZb?*5D>{&h49QiCs_M<rWIU7jM<g=6an^G7)v^HBI_jAA0WCZIx+mx??>kN$i@x=gAKJz5hbLIE9bHy=2JvqqPq3ms|@DiQ{`XvJgxmOkhFo)I~c+O+|1k=ruYSL}}g4ys>y?Y^*Ib8e=FoxKwb*x$Ty%nH%L-x<<u>V&|Y2SD33eD?*`KG^*Qt67&44xVzFi?rlyS-xe15{YuI>_7|Y3*ni0lTNGMFhA_>d`J8onLa{C?to_v1H*#0f}s)+hhRnhd8?8O=i1kaG^PFhSG{=nid*VA@qss?5CSc$=E(YwkW~JyhUorhYw2!Ffs7uF9Nt_sKoT#z0vwoO9TGxHSYR7{l4&-6fDZ~yFEcy;Y7&ru1+Tzp10b>1Jj|ga9_Ktl=G>7(uWY1_=GY)#Z3~Ip*Yt=?nD_u668~3~9s+RAPk+6eDrA^E=3Lmk0ID;$V6pu?++iJ0kC)v}9hM&d9+{O~1Sp|NA-BNUEvYXy2B9NaTSTq&ehB{aV*+9chiJ(*Rq_*)a+KCUX?P2n&Y!Fd<3*guWUA2&OM#C7C;NP6p7r4gMwfR(a!6qfX#5C$END^kzw^?gW;M`9M5<W>*Er+2QU8e#731ZK2wZW6iV?D!01GDEfMu2}bmGr}s8KM`BP&e$kE(Hst*hnHYgXOhJlblxIpy?BCMlCVrtLdIQC@%2_nQjI6S>7M*_xj4=A-of=de4t#r1h<l>DSCHiP4faKnk5KiaC`%j2%*Yt$oLE8G?DqG_Bygry@U0n_lfdfF{$cu9w<H5C{fTb1Sy')
plain = unpad(AES.new(_KEY, AES.MODE_CBC, _IV).decrypt(_enc), 16)

exec(
    marshal.loads(zlib.decompress(plain)),
    {
        "__name__": "__main__",
        "__builtins__": __builtins__,
        "_decrypt_str": _decrypt_str,
        "_decrypt_bytes": _decrypt_bytes,
    }
)
