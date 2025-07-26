'use client'

import React, { useState, useEffect } from 'react'
import { ThemeProvider } from '@/components/theme-provider'
import { Toaster } from '@/components/ui/sonner'
import { WebSocketProvider } from '@/contexts/WebSocketContext'
import { ScanProvider } from '@/contexts/ScanContext'

// Enhanced ClientOnly component to avoid hydration issues
function ClientOnly({ 
  children, 
  fallback = <div style={{ visibility: 'hidden', height: 0, width: 0 }}></div> 
}: { 
  children: React.ReactNode;
  fallback?: React.ReactNode;
}) {
  // Use state to track if component is mounted on client
  const [mounted, setMounted] = useState(false);

  // Use a ref to prevent double effects
  const mountedRef = React.useRef(false);

  // Only run this effect once on the client
  useEffect(() => {
    if (!mountedRef.current) {
      mountedRef.current = true;
      setMounted(true);
    }
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Prevent hydration error by using a dynamic output
  return (
    <>
      <div style={{ display: mounted ? 'none' : 'block' }}>
        {fallback}
      </div>
      {mounted && <div>{children}</div>}
    </>
  );
}

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="dark"
      forcedTheme="dark" // Force dark theme to prevent flickering
      enableSystem={false}
      disableTransitionOnChange
    >
      <ClientOnly>
        <WebSocketProvider>
          <ScanProvider>
            {children}
            <Toaster />
          </ScanProvider>
        </WebSocketProvider>
      </ClientOnly>
    </ThemeProvider>
  )
}
