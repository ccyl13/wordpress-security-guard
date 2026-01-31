import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Info, Tag, Palette, FileText, Code } from 'lucide-react';
import type { WordPressInfo } from '@/types/wordpress-audit';

interface WordPressInfoCardProps {
  info: WordPressInfo;
  isWordPress: boolean;
}

export function WordPressInfoCard({ info, isWordPress }: WordPressInfoCardProps) {
  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-3 text-xl">
          <Info className="w-6 h-6 text-primary" />
          Información del Sitio
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div className="p-4 bg-muted/30 rounded-lg">
            <div className="flex items-center gap-2 text-muted-foreground mb-1">
              <Code className="w-4 h-4" />
              <span className="text-xs uppercase tracking-wide">CMS</span>
            </div>
            <p className="font-semibold">
              {isWordPress ? 'WordPress' : 'No detectado'}
            </p>
          </div>
          
          <div className="p-4 bg-muted/30 rounded-lg">
            <div className="flex items-center gap-2 text-muted-foreground mb-1">
              <Tag className="w-4 h-4" />
              <span className="text-xs uppercase tracking-wide">Versión</span>
            </div>
            <p className={info.version ? 'font-semibold text-yellow-400' : 'font-semibold text-green-400'}>
              {info.version || 'Oculta'}
            </p>
          </div>
          
          <div className="p-4 bg-muted/30 rounded-lg">
            <div className="flex items-center gap-2 text-muted-foreground mb-1">
              <Palette className="w-4 h-4" />
              <span className="text-xs uppercase tracking-wide">Tema</span>
            </div>
            <p className="font-semibold font-mono text-sm">
              {info.theme || 'No detectado'}
            </p>
          </div>
          
          <div className="p-4 bg-muted/30 rounded-lg">
            <div className="flex items-center gap-2 text-muted-foreground mb-1">
              <FileText className="w-4 h-4" />
              <span className="text-xs uppercase tracking-wide">Generator Meta</span>
            </div>
            <p className={info.generator ? 'font-semibold text-yellow-400' : 'font-semibold text-green-400'}>
              {info.generator ? 'Expuesto ⚠️' : 'Oculto ✓'}
            </p>
          </div>
        </div>
        
        {(info.version || info.generator) && (
          <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
            <p className="text-sm text-yellow-400">
              💡 <strong>Recomendación:</strong> Oculta la versión de WordPress y el meta tag generator para dificultar la identificación de vulnerabilidades conocidas.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
