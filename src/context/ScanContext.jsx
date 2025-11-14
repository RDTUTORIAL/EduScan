import { createContext, useContext } from 'react';

export const ScanContext = createContext({
  history: [],
  addHistoryEntry: () => {},
  removeHistoryEntry: () => {},
  clearHistory: () => {},
  status: 'Ready',
  setStatus: () => {},
  reloadHistoryEntry: () => {},
});

export const useScanContext = () => useContext(ScanContext);
