import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import './tauriBridge.ts';
import App from './App.tsx';
import './index.css';

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {
      // 桌面 WebView 等环境不支持时静默降级
    });
  });
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
