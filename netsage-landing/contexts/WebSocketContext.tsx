"use client"

import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback, useRef } from "react"
import { io, Socket } from "socket.io-client"
import { ScanStatus } from "@/services/api"

// Define WebSocket connection states
export type ConnectionStatus = "connected" | "disconnected" | "connecting" | "error"

// Define WebSocket event data types
export interface ScanUpdateEvent {
  requestId: string
  status: ScanStatus
  previousStatus?: ScanStatus
  timestamp: string
}

export interface NotificationEvent {
  message: string
  type: "info" | "warning" | "error"
  timestamp: string
}

// Define WebSocket context interface
interface WebSocketContextType {
  socket: Socket | null
  status: ConnectionStatus
  subscribeTo: (requestId: string) => void
  unsubscribeFrom: (requestId: string) => void
  reconnect: () => void
}

// Default context value
const defaultContextValue: WebSocketContextType = {
  socket: null,
  status: "disconnected",
  subscribeTo: () => { console.log("Default subscribeTo called"); },
  unsubscribeFrom: () => { console.log("Default unsubscribeFrom called"); },
  reconnect: () => { console.log("Default reconnect called"); },
};

// Create context with default values
const WebSocketContext = createContext<WebSocketContextType>(defaultContextValue)

// WebSocket Provider Props
interface WebSocketProviderProps {
  children: ReactNode
}

// Socket URL hardcoded for reliability
const SOCKET_URL = "http://localhost:4000"

// WebSocket Provider Component
export function WebSocketProvider({ children }: WebSocketProviderProps) {
  // Use refs to manage socket instance and prevent state updates during SSR
  const socketRef = useRef<Socket | null>(null);
  const initAttemptedRef = useRef<boolean>(false);
  
  // States for UI and tracking
  const [socket, setSocket] = useState<Socket | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [initialized, setInitialized] = useState<boolean>(false);
  
  // Avoid any logging during server rendering
  useEffect(() => {
    if (typeof window !== 'undefined') {
      console.log(`WebSocketProvider status: ${status}, Socket: ${socket ? `${socket.id} (${socket.connected ? 'connected' : 'disconnected'})` : 'null'}, Initialized: ${initialized}`);
    }
  }, [status, socket, initialized]);
  
  // Initialize socket connection with improved handling
  const connectWebSocket = useCallback(() => {
    // Skip if we're on server side
    if (typeof window === 'undefined') return;
    
    // Skip if already attempted initialization
    if (initAttemptedRef.current) {
      console.log("Socket initialization already attempted, skipping");
      return;
    }
    
    try {
      console.log("Initializing WebSocket connection to:", SOCKET_URL);
      setStatus("connecting");
      initAttemptedRef.current = true;
      
      // Close existing socket if any
      if (socketRef.current) {
        console.log("Closing existing socket connection");
        socketRef.current.disconnect();
        socketRef.current = null;
      }

      // Create socket with optimized configuration
      const socketOptions = {
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        timeout: 10000,
        reconnectionDelayMax: 5000,
        forceNew: true,
        autoConnect: true,
      };
      
      console.log("Creating new Socket.IO connection with options:", JSON.stringify(socketOptions));
      const newSocket = io(SOCKET_URL, socketOptions);
      socketRef.current = newSocket;
      
      // Track the last time we updated status to avoid flashing
      const statusDebounceTime = 800;
      let lastStatusUpdate = Date.now() - statusDebounceTime;
      
      const updateStatus = (newStatus: ConnectionStatus) => {
        const now = Date.now();
        if (now - lastStatusUpdate >= statusDebounceTime) {
          lastStatusUpdate = now;
          setStatus(newStatus);
        }
      };

      // Clear any previous event listeners
      newSocket.removeAllListeners();
      
      // Set up core event handlers
      newSocket.on("connect", () => {
        console.log("✅ WebSocket connected, ID:", newSocket.id);
        updateStatus("connected");
        
        // Update the state socket after successful connection
        setSocket(newSocket);
        setInitialized(true);
      });

      newSocket.on("disconnect", (reason) => {
        console.log(`⚠️ WebSocket disconnected, reason: ${reason}`);
        if (reason !== "io client disconnect") {
          updateStatus("disconnected");
        }
      });

      newSocket.on("connect_error", (error) => {
        console.error("❌ WebSocket connection error:", error.message);
        updateStatus("error");
      });
      
      // Handle reconnection separately to avoid UI flicker
      newSocket.io.on("reconnect", (attempt: number) => {
        console.log(`✅ Socket.IO reconnected after ${attempt} attempts`);
        updateStatus("connected");
      });
      
      // Set the socket in state for consumers
      setSocket(newSocket);
      
      // Return the socket for direct access if needed
      return newSocket;
    } catch (error) {
      console.error("Failed to initialize WebSocket:", error);
      setStatus("error");
      return null;
    }
  }, [])

  // Create an isomorphic layout effect to safely handle initialization
  const useIsomorphicLayoutEffect = typeof window !== 'undefined' ? useEffect : () => {};
  
  // Initialize connection only after initial render is complete
  useIsomorphicLayoutEffect(() => {
    // Skip server-side execution entirely
    if (typeof window === 'undefined') return;
    
    // Wait until after hydration to initialize socket
    const hydrationComplete = () => {
      // Double RAF ensures we're past hydration and in a stable client render
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (!initAttemptedRef.current) {
            console.log("WebSocketProvider initializing after hydration");
            connectWebSocket();
          }
        });
      });
    };
    
    // Start the initialization sequence
    hydrationComplete();
    
    // Cleanup function
    return () => {
      if (socketRef.current) {
        console.log("WebSocketProvider unmounting, disconnecting socket");
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, []); // Empty dependency array to run only once
  
  // Subscribe to scan updates - simplified to avoid reconnection loops
  const subscribeTo = useCallback(
    (requestId: string) => {
      if (!socket) {
        console.warn(`Cannot subscribe to ${requestId}: socket is null`);
        return;
      }
      
      // Only emit subscribe event if connected
      if (socket.connected) {
        console.log(`Subscribing to updates for scan ${requestId} (socket: ${socket.id})`);
        socket.emit("subscribe", requestId);
      } else {
        console.log(`Waiting for connection to subscribe to ${requestId}`);
        
        // Use a one-time event handler
        const onceConnected = () => {
          console.log(`Now connected, subscribing to ${requestId}`);
          socket.emit("subscribe", requestId);
        };
        
        socket.once("connect", onceConnected);
      }
    },
    [socket]
  )

  // Unsubscribe from scan updates
  const unsubscribeFrom = useCallback(
    (requestId: string) => {
      if (socket && socket.connected) {
        console.log(`Unsubscribing from updates for scan ${requestId}`)
        socket.emit("unsubscribe", requestId)
      }
    },
    [socket]
  )

  // Reconnect to WebSocket server
  const reconnect = useCallback(() => {
    connectWebSocket()
  }, [connectWebSocket])

  // Context value
  const value = {
    socket,
    status,
    subscribeTo,
    unsubscribeFrom,
    reconnect,
  }

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>
}

// Hook for using the WebSocket context
export function useWebSocket() {
  const context = useContext(WebSocketContext);
  return context;
}

// Hook for subscribing to scan updates - simplified version
export function useScanSubscription(
  requestId: string | null,
  onUpdate?: (data: ScanUpdateEvent) => void
) {
  const { socket, subscribeTo, unsubscribeFrom } = useWebSocket();
  
  // Use ref to track current requestId to avoid stale closures
  const requestIdRef = useRef(requestId);
  
  // Update ref when requestId changes
  useEffect(() => {
    requestIdRef.current = requestId;
  }, [requestId]);

  useEffect(() => {
    // Skip if no requestId or socket
    if (!requestId || !socket) return;
    
    console.log(`Setting up subscription for scan ${requestId}`);
    
    // Set up scan update listener with stable reference to current requestId
    const handleScanUpdate = (data: ScanUpdateEvent) => {
      // Use ref to get current requestId
      if (data.requestId === requestIdRef.current && onUpdate) {
        console.log(`Processing update for scan ${data.requestId}:`, data.status);
        onUpdate(data);
      }
    };

    // Add event listener first before subscribing
    socket.on("scanUpdate", handleScanUpdate);
    
    // Subscribe to updates
    subscribeTo(requestId);

    // Cleanup function
    return () => {
      const currentId = requestIdRef.current;
      if (currentId) {
        console.log(`Cleaning up subscription for scan ${currentId}`);
        socket.off("scanUpdate", handleScanUpdate);
        unsubscribeFrom(currentId);
      }
    };
  }, [socket, subscribeTo, unsubscribeFrom, onUpdate, requestId]);
}

// Hook for listening to system notifications
export function useSystemNotifications(
  onNotification?: (data: NotificationEvent) => void
) {
  const { socket } = useWebSocket();

  useEffect(() => {
    if (!socket) return;

    // Set up notification listener
    const handleNotification = (data: NotificationEvent) => {
      console.log(`Received system notification:`, data);
      if (onNotification) onNotification(data);
    };

    // Listen for notification events
    socket.on("notification", handleNotification);

    // Cleanup on unmount
    return () => {
      socket.off("notification", handleNotification);
    };
  }, [socket, onNotification]);
}
