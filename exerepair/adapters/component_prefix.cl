/* Bounded streaming filter. Reject impossible prefixes before further RC4 work. */
__constant uint K[64]={
 0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
 0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
 0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
 0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
 0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
 0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
 0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
 0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
__constant uint R[16]={7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21};
inline void digest(uint value,__private uint *result) {
 uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
 #pragma unroll
 for(uint i=0;i<64;i++) {
  uint f,g;
  if(i<16){f=(b&c)|(~b&d);g=i;}
  else if(i<32){f=(d&b)|(~d&c);g=(5*i+1)&15;}
  else if(i<48){f=b^c^d;g=(3*i+5)&15;}
  else{f=c^(b|~d);g=(7*i)&15;}
  uint w=g==0?value:(g==1?128:(g==14?32:0));
  uint next=b+rotate(a+f+K[i]+w,R[(i/16)*4+(i&3)]);
  a=d;d=c;c=b;b=next;
 }
 result[0]=a+0x67452301;result[1]=b+0xefcdab89;
 result[2]=c+0x98badcfe;result[3]=d+0x10325476;
}
inline int nextbyte(__private uchar *s,__global const uchar *cipher,
                    __private uint *pos,__private uint *j) {
 if(*pos>=128)return -1;
 uint i=*pos+1;*j=(*j+s[i])&255;
 uchar t=s[i];s[i]=s[*j];s[*j]=t;
 return cipher[(*pos)++]^s[((uint)s[i]+s[*j])&255];
}
inline int getbit(__private uchar *s,__global const uchar *cipher,
                 __private uint *pos,__private uint *j,
                 __private uint *tag,__private uint *left) {
 if(*left==0){int next=nextbyte(s,cipher,pos,j);if(next<0)return -1;*tag=next;*left=8;}
 int value=(*tag>>7)&1;*tag=(*tag<<1)&255;(*left)--;return value;
}
inline int getgamma(__private uchar *s,__global const uchar *cipher,
                   __private uint *pos,__private uint *j,
                   __private uint *tag,__private uint *left) {
 uint value=1;
 for(uint i=0;i<31;i++){
  int v=getbit(s,cipher,pos,j,tag,left);if(v<0)return -1;value=(value<<1)|v;
  v=getbit(s,cipher,pos,j,tag,left);if(v<0)return -1;if(v==0)return (int)value;
 }
 return -2;
}
inline uchar valid(__private uchar *s,__global const uchar *cipher,uint maximum) {
 uint pos=0,j=0,tag=0,left=0,out=1,state=2,previous=0;
 nextbyte(s,cipher,&pos,&j); /* The first literal still advances RC4 state. */
 for(uint iteration=0;iteration<4096;iteration++) {
  int v=getbit(s,cipher,&pos,&j,&tag,&left);
  if(v<0)return 1;
  if(v==0){if(nextbyte(s,cipher,&pos,&j)<0)return 1;out++;state=2;}
  else {
   v=getbit(s,cipher,&pos,&j,&tag,&left);if(v<0)return 1;
   if(v==0){
    int raw=getgamma(s,cipher,&pos,&j,&tag,&left);if(raw==-1)return 1;if(raw<0)return 0;
    int diff=raw-(int)state;if(diff<0)return 0;
    uint offset,length;
    if(diff==0){
     offset=previous;raw=getgamma(s,cipher,&pos,&j,&tag,&left);
     if(raw==-1)return 1;if(raw<0)return 0;length=(uint)raw;
    }else{
     raw=nextbyte(s,cipher,&pos,&j);if(raw<0)return 1;
     offset=(((uint)diff-1)<<8)|(uint)raw;previous=offset;
     raw=getgamma(s,cipher,&pos,&j,&tag,&left);if(raw==-1)return 1;if(raw<0)return 0;
     length=(uint)raw+(offset>=0x7d00)+(offset>=0x500)+2*(offset<0x80);
    }
    if(offset==0 || offset>out || length>maximum-out)return 0;
    out+=length;state=1;
   }else{
    v=getbit(s,cipher,&pos,&j,&tag,&left);if(v<0)return 1;
    if(v==0){
     int raw=nextbyte(s,cipher,&pos,&j);if(raw<0)return 1;
     uint value=(uint)raw,offset=value>>1;
     if(offset==0 || offset>out)return 0;
     previous=offset;out+=2+(value&1);state=1;
    }else{
     uint offset=0;
     for(uint n=0;n<4;n++){v=getbit(s,cipher,&pos,&j,&tag,&left);if(v<0)return 1;offset=(offset<<1)|v;}
     if(offset>out)return 0;out++;state=2;
    }
   }
  }
  if(out>maximum)return 0;
 }
 return 0;
}
__kernel void filter(__global const uchar *prefix,__global const uchar *cipher,
                     uint start,uint count,uint maximum,__global uchar *flags) {
 uint n=(uint)get_global_id(0);if(n>=count)return;
 uint words[4];digest(start+n,words);
 uchar s[256];
 for(uint i=0;i<256;i++)s[i]=(uchar)i;
 uint j=0;
 for(uint i=0;i<256;i++){
  uint index=i&31;
  uint key=index<16?prefix[index]:((words[(index-16)/4]>>(((index-16)&3)*8))&255);
  j=(j+s[i]+key)&255;uchar t=s[i];s[i]=s[j];s[j]=t;
 }
 flags[n]=valid(s,cipher,maximum);
}
