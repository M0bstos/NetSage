'use client'

import React, { useState, useEffect } from 'react'
import { WebSocketProvider } from '@/contexts/WebSocketContext'
import { ScanProvider } from '@/contexts/ScanContext'
import { ThemeProvider } from '@/components/theme-provider'
import { Toaster } from '@/components/ui/sonner'

export function Providers({ children }: { children: React.ReactNode }) {
  // Using React 18's useEffect for client-side only code
  const [mounted, setMounted] = useState(false)
  
  useEffect(() => {
    setMounted(true)
  }, [])
  
  // Prevent hydration issues by only rendering providers on client side
  if (!mounted) {
    return <>{children}</>
  }
  
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
    >
      <WebSocketProvider>
        <ScanProvider>
          {children}
          <Toaster />
        </ScanProvider>
      </WebSocketProvider>
    </ThemeProvider>
  )
}
