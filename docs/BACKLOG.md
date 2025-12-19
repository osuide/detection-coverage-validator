# A13E Development Backlog

## Features

### Heatmap Enhancements

- [x] **Display detection names in heatmap tooltip** *(Completed 2025-12-19)*
  - Shows associated detection names when hovering over technique cells
  - Backend updated to include detection names in `/coverage/{id}/techniques` endpoint
  - Tooltip shows up to 5 detection names, click for full list

## Documentation

- [ ] **Create GCP connection guide**
  - Product supports GCP but all connection guides are AWS-focused
  - Create `connecting-gcp-projects.md` documentation
  - Priority: Medium

- [ ] **Apply UK English corrections**
  - Fix remaining US English spellings in documentation
  - See docs review notes for specific instances
  - Priority: Low

## Technical Debt

- [ ] **Code splitting for frontend bundle**
  - Bundle currently exceeds 500KB warning threshold
  - Implement dynamic imports for route-based splitting
  - Priority: Low
