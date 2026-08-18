import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react';

export default function Toast({ toast, onDismiss }) {
  if (!toast) return null;

  const icons = {
    success: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
    warning: <AlertTriangle className="w-4 h-4 text-amber-400" />,
    error: <XCircle className="w-4 h-4 text-red-400" />,
    info: <Info className="w-4 h-4 text-sky-400" />
  };

  const borders = {
    success: 'border-emerald-500/40 bg-emerald-950/90 text-emerald-100',
    warning: 'border-amber-500/40 bg-amber-950/90 text-amber-100',
    error: 'border-red-500/40 bg-red-950/90 text-red-100',
    info: 'border-sky-500/40 bg-sky-950/90 text-sky-100'
  };

  return (
    <div className="fixed bottom-5 right-5 z-50 animate-slideUp max-w-md">
      <div className={`p-3.5 rounded-xl border backdrop-blur-md shadow-2xl flex items-start gap-3 text-xs ${borders[toast.type || 'info']}`}>
        <div className="shrink-0 mt-0.5">{icons[toast.type || 'info']}</div>
        <div className="flex-1">
          {toast.title && <div className="font-bold mb-0.5">{toast.title}</div>}
          <div className="text-slate-300 leading-relaxed">{toast.message}</div>
        </div>
        <button
          onClick={onDismiss}
          className="text-slate-400 hover:text-white transition-colors p-1"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
