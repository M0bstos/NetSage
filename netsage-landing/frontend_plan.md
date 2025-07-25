# Frontend Implementation Plan

This document outlines the step-by-step plan for integrating the NetSage frontend with the backend services. Each step is designed to be independently implementable and testable.

## 1. Setup Dependencies

- [x] Install Socket.IO client
- [x] Install any other required dependencies (file-saver, etc.)

```bash
pnpm add socket.io-client file-saver @types/file-saver
```

## 2. Create API Service Layer

- [x] Create API service module (`services/api.ts`)
  - [x] Implement function for submitting scan requests
  - [x] Implement function for retrieving scan reports
  - [x] Implement function for checking scan status
  - [x] Implement function for retrying failed scans
  - [x] Add error handling utilities
  - [x] Add response type definitions

## 3-6. UI Integration with Mock Implementation (Completed)

- [x] Implement UI component integration with local state
  - [x] Implement form validation and submission handling
  - [x] Add mock connection management
  - [x] Add simulated state transitions and progress tracking
  - [x] Add toast notification system

- [x] Integrate all UI components in page.tsx
  - [x] Add state variables for URL, progress, scan state, and reports
  - [x] Connect the scan input form with validation
  - [x] Add form submission with loading state
  - [x] Connect ScanProgressModal with simulated progress
  - [x] Add ReportPreview with mock report data
  - [x] Connect ReportActions with mock functionality
  - [x] Add WebSocketStatus indicator with simulated states
  - [x] Implement toast notifications for status updates

- [x] Add mock data flow to simulate backend interaction
  - [x] Create simulated scan progress function
  - [x] Add mock report data generation
  - [x] Implement simulated download/share functionality

## 7. Replace Mock Implementation with Real Backend Integration

- [x] Create WebSocket context module (`contexts/WebSocketContext.tsx`)
  - [x] Implement Socket.IO connection to backend
  - [x] Implement subscription to scan updates
  - [x] Implement event handling for state changes
  - [x] Implement reconnection logic
  - [x] Add real status reporting

- [x] Create Scan context module (`contexts/ScanContext.tsx`)
  - [x] Implement real scan state management using API
  - [x] Replace mock submission with actual API calls
  - [x] Implement real scan status tracking via WebSocket
  - [x] Add real report fetching from backend
  - [x] Add proper error handling for API/WebSocket

- [x] Update app/page.tsx to use real backend
  - [x] Replace mock implementation with context providers
  - [x] Connect scan form to real API
  - [x] Update progress modal to use real data
  - [x] Update report modal to use real data
  - [x] Connect toast notifications to real events

## 8. Implement Utilities

- [ ] Create utility functions for downloading reports
  - [ ] Implement Markdown to downloadable file conversion
  - [ ] Add filename formatting

- [ ] Add state mapping utilities
  - [ ] Map backend states to frontend UI states
  - [ ] Add progress calculation logic

## 9. Testing

- [ ] Test WebSocket connection and event handling
- [ ] Test scan submission flow
- [ ] Test report retrieval and display
- [ ] Test error handling scenarios
- [ ] Test download functionality

## 10. Performance Optimization

- [ ] Add memoization for expensive renders
- [ ] Optimize WebSocket subscription management
- [ ] Add loading states and placeholders

## 11. Optional Enhancements

- [ ] Add scan history tracking
- [ ] Implement shareable report links
- [ ] Add offline support/caching
- [ ] Implement advanced visualization for reports
