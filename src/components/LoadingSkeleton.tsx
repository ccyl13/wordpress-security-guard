function Sk({ w, h, mb }: { w: string; h: string; mb?: string }) {
  return <div className="skeleton rounded" style={{ width: w, height: h, marginBottom: mb || 0 }}/>;
}

export function AuditLoadingSkeleton() {
  return (
    <div className="space-y-4">
      {/* header */}
      <div className="flex justify-between items-start mb-6">
        <div className="space-y-2"><Sk w="260px" h="14px"/><Sk w="160px" h="12px"/></div>
        <Sk w="110px" h="34px"/>
      </div>

      {/* score + info */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="result-card p-6 flex flex-col items-center gap-4">
          <Sk w="120px" h="10px"/>
          <div className="w-36 h-36 rounded-full skeleton"/>
          <Sk w="70px" h="28px"/>
        </div>
        <div className="result-card p-5 lg:col-span-2 space-y-3">
          <Sk w="140px" h="12px" mb="8px"/>
          {[180,140,120,160,100].map((w,i) => (
            <div key={i} className="flex justify-between items-center py-2 border-b border-white/[0.04] last:border-0">
              <Sk w="100px" h="10px"/>
              <Sk w={w/3+'px'} h="10px"/>
            </div>
          ))}
        </div>
      </div>

      {/* two cols */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[0,1].map(k => (
          <div key={k} className="result-card p-5 space-y-3">
            <div className="flex justify-between mb-2"><Sk w="110px" h="11px"/><Sk w="60px" h="11px"/></div>
            {[...Array(6)].map((_,j) => (
              <div key={j} className="flex items-center gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-white/10 shrink-0"/>
                <Sk w={(70+j*15)+'px'} h="9px"/>
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* recs */}
      <div className="result-card p-5 space-y-4">
        <Sk w="130px" h="11px"/>
        {[...Array(3)].map((_,i) => (
          <div key={i} className="flex gap-3 items-start">
            <div className="w-2 h-2 rounded-full bg-white/10 mt-1 shrink-0"/>
            <div className="flex-1 space-y-2">
              <Sk w="200px" h="11px"/>
              <Sk w="100%" h="9px"/>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
