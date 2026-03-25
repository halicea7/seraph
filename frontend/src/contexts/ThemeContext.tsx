import { createContext, useContext, useEffect, useState } from 'react'

export type Theme = 'blue' | 'mono'

interface ThemeContextValue {
  theme: Theme
  setTheme: (t: Theme) => void
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'blue',
  setTheme: () => {},
})

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    return (localStorage.getItem('seraph_theme') as Theme) ?? 'blue'
  })

  function setTheme(t: Theme) {
    setThemeState(t)
    localStorage.setItem('seraph_theme', t)
  }

  // Sync to html data-theme attribute so CSS can cascade
  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  return useContext(ThemeContext)
}
