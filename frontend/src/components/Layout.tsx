import { Moon, ShieldCheck, Sun } from "lucide-react";
import { Link, Outlet } from "react-router-dom";
import { useTheme } from "../contexts/ThemeContext";

export default function Layout() {
  const { dark, toggle } = useTheme();

  return (
    <div className="min-h-screen flex flex-col bg-zinc-100 dark:bg-zinc-800">
      <header className="border-b border-zinc-300 bg-white dark:border-zinc-700 dark:bg-zinc-900 px-6 py-3 flex items-center gap-3 shrink-0">
        <Link to="/" className="flex items-center gap-2 hover:text-emerald-500 dark:hover:text-emerald-400 transition-colors">
          <ShieldCheck className="text-emerald-500 dark:text-emerald-400" size={22} />
          <span className="font-semibold text-lg tracking-tight">Sasty</span>
        </Link>
        <span className="text-zinc-400 dark:text-zinc-600 text-sm ml-1">Static Analysis Review Tool</span>
        <div className="ml-auto">
          <button
            onClick={toggle}
            title={dark ? "Switch to light mode" : "Switch to dark mode"}
            className="p-2 rounded text-zinc-400 hover:text-zinc-700 dark:text-zinc-500 dark:hover:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
          >
            {dark ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>
      </header>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
