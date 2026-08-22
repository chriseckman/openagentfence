export const GUARD_ROLES = ["text_injection", "visual_injection", "task_alignment"] as const;

export type GuardRole = (typeof GUARD_ROLES)[number];
