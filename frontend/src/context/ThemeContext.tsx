import { createContext, useContext, useState, ReactNode } from 'react';

export interface SeverityColors {
  critical: string;
  high: string;
  medium: string;
  low: string;
}

export interface ThemeColors {
  severity: SeverityColors;
  accent: string;
  chartLine: string;
}

const defaultTheme: ThemeColors = {
  severity: {
    critical: '#CB181D',
    high: '#F16913',
    medium: '#e6b400',
    low: '#1B75BE',
  },
  accent: '#7A4832',
  chartLine: '#FFFFFF',
};

interface ThemeContextValue {
  colors: ThemeColors;
  setColors: (colors: ThemeColors) => void;
  resetColors: () => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  colors: defaultTheme,
  setColors: () => {},
  resetColors: () => {},
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [colors, setColorsState] = useState<ThemeColors>(defaultTheme);

  const setColors = (next: ThemeColors) => setColorsState(next);
  const resetColors = () => setColorsState(defaultTheme);

  return (
    <ThemeContext.Provider value={{ colors, setColors, resetColors }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}

export { defaultTheme };
