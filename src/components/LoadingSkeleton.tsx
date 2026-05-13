const S = ({ w, h, mb }: { w:string; h:string; mb?:string }) => (
  <div className="skeleton rounded" style={{ width:w, height:h, marginBottom:mb||0 }}/>
);

export function AuditLoadingSkeleton() {
  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex justify-between items-start mb-6">
        <div className="space-y-2"><S w="260px" h="12px"/><S w="180px" h="20px"/><S w="120px" h="10px"/></div>
        <S w="120px" h="38px"/>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-2xl p-6 flex flex-col items-center gap-4">
          <S w="80px" h="10px"/>
          <div className="w-36 h-36 rounded-full skeleton"/>
          <S w="70px" h="28px"/>
        </div>
        <div className="lg:col-span-2 glass rounded-2xl p-5 space-y-3">
          <S w="140px" h="12px" mb="8px"/>
          {[...Array(5)].map((_,i) => (
            <div key={i} className="flex justify-between items-center py-2 border-b border-white/[0.04]">
              <S w="120px" h="10px"/><S w="70px" h="10px"/>
            </div>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[...Array(2)].map((_,i) => (
          <div key={i} className="glass rounded-2xl p-5 space-y-3">
            <S w="100px" h="11px" mb="4px"/>
            {[...Array(6)].map((_,j) => (
              <div key={j} className="flex items-center gap-2">
                <div className="w-1 h-1 rounded-full bg-white/10 shrink-0"/>
                <S w={(70+j*15)+'px'} h="9px"/>
              </div>
            ))}
          </div>
        ))}
      </div>
      <div className="glass rounded-2xl p-5 space-y-4">
        <S w="120px" h="11px"/>
        {[...Array(3)].map((_,i) => (
          <div key={i} className="flex gap-3">
            <div className="w-2 h-2 rounded-full bg-white/10 mt-1 shrink-0"/>
            <div className="flex-1 space-y-2"><S w="200px" h="11px"/><S w="100%" h="9px"/></div>
          </div>
        ))}
      </div>
    </div>
  );
}
