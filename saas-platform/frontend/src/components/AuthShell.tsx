import { ReactNode } from "react";

import Brand from "./Brand";

/** Flat dark frame shared by the sign-in and registration screens. */
export default function AuthShell({ eyebrow, title, children, aside }: {
  eyebrow: string;
  title: string;
  children: ReactNode;
  aside: ReactNode;
}) {
  return (
    <div className="flex min-h-screen flex-col bg-dark text-on-dark">
      <header className="border-b border-dark-line">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-5 py-5 sm:px-8">
          <Brand />
          {aside}
        </div>
      </header>
      <main className="flex flex-1 items-start justify-center px-5 py-14 sm:items-center">
        <div className="w-full max-w-[26rem]">
          <div className="eyebrow mb-4">{eyebrow}</div>
          <h1 className="mb-8 text-[2.1rem] font-extrabold leading-[1.05] tracking-[-0.02em]">{title}</h1>
          <div className="border border-dark-line bg-dark-surface p-6 sm:p-7">{children}</div>
        </div>
      </main>
      <div className="border-t border-dark-line">
        <div className="mx-auto max-w-6xl px-5 py-4 font-mono text-[0.7rem] text-dim-dark sm:px-8">
          Scan only systems you own or are authorized to test.
        </div>
      </div>
    </div>
  );
}

export function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p role="alert" className="border-l-2 border-brand bg-brand/[0.06] px-3 py-2 text-sm text-on-dark">
      {message}
    </p>
  );
}
