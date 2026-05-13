const Pulse = ({ w, h, mb }: { w: string; h: string; mb?: string }) => (
  <div style={{
    width: w, height: h, borderRadius: '4px',
    background: 'linear-gradient(90deg, #0d0d1e 25%, #16163a 50%, #0d0d1e 75%)',
    backgroundSize: '200% 100%',
    animation: 'shimmer 1.5s infinite',
    marginBottom: mb || '0',
  }}/>
);

export function AuditLoadingSkeleton() {
  return (
    <div style={{ fontFamily: 'JetBrains Mono, monospace' }}>
      <style>{`
        @keyframes shimmer {
          0% { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>

      {/* top bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <div style={{ fontSize: '9px', color: '#ffffff15', letterSpacing: '2px', marginBottom: '6px' }}>SITIO AUDITADO</div>
          <Pulse w="280px" h="16px" mb="6px"/>
          <Pulse w="120px" h="10px"/>
        </div>
        <Pulse w="120px" h="36px"/>
      </div>

      {/* score + info row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '12px', marginBottom: '12px' }}>
        <div style={{ background: '#08080f', border: '1px solid #ffffff08', borderRadius: '10px', padding: '24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <Pulse w="80px" h="10px"/>
          <div style={{ width: '120px', height: '120px', borderRadius: '50%', border: '8px solid #0d0d1e', position: 'relative', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', inset: 0, background: 'linear-gradient(90deg,#0d0d1e 25%,#16163a 50%,#0d0d1e 75%)', backgroundSize: '200% 100%', animation: 'shimmer 1.5s infinite' }}/>
          </div>
          <Pulse w="60px" h="24px"/>
        </div>
        <div style={{ background: '#08080f', border: '1px solid #ffffff08', borderRadius: '10px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <Pulse w="140px" h="12px"/>
          {[...Array(5)].map((_,i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Pulse w="120px" h="10px"/>
              <Pulse w="60px" h="10px"/>
            </div>
          ))}
        </div>
      </div>

      {/* two col row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
        {[...Array(2)].map((_,i) => (
          <div key={i} style={{ background: '#08080f', border: '1px solid #ffffff08', borderRadius: '10px', padding: '20px' }}>
            <Pulse w="100px" h="11px" mb="14px"/>
            {[...Array(6)].map((_,j) => (
              <div key={j} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <div style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#ffffff08', flexShrink: 0 }}/>
                <Pulse w={80 + j * 12 + 'px'} h="9px"/>
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* recs */}
      <div style={{ background: '#08080f', border: '1px solid #ffffff08', borderRadius: '10px', padding: '20px' }}>
        <Pulse w="120px" h="11px" mb="14px"/>
        {[...Array(3)].map((_,i) => (
          <div key={i} style={{ display: 'flex', gap: '10px', marginBottom: '14px', alignItems: 'flex-start' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#ffffff08', marginTop: '3px', flexShrink: 0 }}/>
            <div style={{ flex: 1 }}>
              <Pulse w="200px" h="11px" mb="6px"/>
              <Pulse w="100%" h="9px"/>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
