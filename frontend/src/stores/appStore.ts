import { create } from 'zustand'
import type { Project, ToolRegistry } from '@/types'

interface AppState {
  // State
  projects: Project[]
  selectedProject: Project | null
  toolStatus: ToolRegistry | null

  // Actions
  setProjects: (projects: Project[]) => void
  setSelectedProject: (project: Project | null) => void
  setToolStatus: (status: ToolRegistry) => void
  addProject: (project: Project) => void
  removeProject: (id: string) => void
  updateProject: (project: Project) => void
}

export const useAppStore = create<AppState>((set) => ({
  projects: [],
  selectedProject: null,
  toolStatus: null,

  setProjects: (projects) => set({ projects }),

  setSelectedProject: (project) => set({ selectedProject: project }),

  setToolStatus: (status) => set({ toolStatus: status }),

  addProject: (project) =>
    set((state) => ({ projects: [project, ...state.projects] })),

  removeProject: (id) =>
    set((state) => ({
      projects: state.projects.filter((p) => p.id !== id),
      selectedProject:
        state.selectedProject?.id === id ? null : state.selectedProject,
    })),

  updateProject: (project) =>
    set((state) => ({
      projects: state.projects.map((p) => (p.id === project.id ? project : p)),
      selectedProject:
        state.selectedProject?.id === project.id
          ? project
          : state.selectedProject,
    })),
}))
