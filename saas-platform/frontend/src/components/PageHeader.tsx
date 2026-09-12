import { ReactNode } from "react";

interface Props {
  eyebrow: string;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}

/** Dark title band at the top of every in-app page. */
export default function PageHeader({ eyebrow, title, description, actions }: Props) {
  return (
    <div className="border-b border-dark-line bg-dark text-on-dark">
      <div className="mx-auto flex max-w-6xl flex-wrap items-end justify-between gap-6 px-5 pb-9 pt-10 sm:px-8">
        <div className="min-w-0">
          <div className="eyebrow mb-3">{eyebrow}</div>
          <h1 className="break-words text-[clamp(1.8rem,3.4vw,2.5rem)] font-extrabold leading-[1.05] tracking-[-0.02em]">
            {title}
          </h1>
          {description && <p className="mt-3 max-w-[60ch] text-[0.95rem] text-dim-dark">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap gap-3">{actions}</div>}
      </div>
    </div>
  );
}
