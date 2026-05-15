import { render, screen, waitFor, within, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import Findings from '../../../src/pages/Findings'
import { getFindings } from '../../../src/api'

vi.mock('../../../src/api', () => ({
  getFindings: vi.fn(),
  API_BASE: 'http://127.0.0.1:8000',
}))

// ── Shared fixtures ───────────────────────────────────────────────────────────

const criticalFinding = {
  id: 'finding-crit-1',
  severity: 'critical',
  category: 'injection',
  title: 'SQL Injection in Login',
  target: 'api.example.com',
  description: 'Parameterized queries not used.',
  remediation: 'Use prepared statements.',
  discovered_at: '2026-05-14T10:00:00Z',
  cvss: 9.8,
  cve: 'CVE-2026-1234',
}

const highFinding = {
  id: 'finding-high-1',
  severity: 'high',
  category: 'xss',
  title: 'Stored XSS in Comments',
  target: 'web.example.com',
  description: 'User input rendered without escaping.',
  remediation: 'Sanitize output.',
  discovered_at: '2026-05-13T08:30:00Z',
  cvss: 7.5,
}

const mediumFinding = {
  id: 'finding-med-1',
  severity: 'medium',
  category: 'misconfiguration',
  title: 'Missing Security Headers',
  target: 'api.example.com',
  description: 'Several headers are absent.',
  remediation: 'Add CSP and HSTS headers.',
  discovered_at: '2026-05-15T14:00:00Z',
}

const allFindings = [criticalFinding, highFinding, mediumFinding]

// ── Helper ────────────────────────────────────────────────────────────────────

function renderFindings() {
  return render(
    <MemoryRouter>
      <Findings />
    </MemoryRouter>,
  )
}

// Finding titles show up in both the list row and the detail sidebar,
// so we use getAllByText and check the count instead of getByText.

// ── Loading ───────────────────────────────────────────────────────────────────

describe('Findings — loading state', () => {
  it('shows loading text while fetching', () => {
    vi.mocked(getFindings).mockReturnValue(new Promise(() => {}))
    renderFindings()
    expect(screen.getByText(/Synchronizing findings feed/i)).toBeInTheDocument()
  })
})

// ── Severity filter ───────────────────────────────────────────────────────────

describe('Findings — severity filtering', () => {
  beforeEach(() => {
    vi.mocked(getFindings).mockResolvedValue({ findings: allFindings })
  })

  it('shows all findings by default', async () => {
    renderFindings()

    // Wait for data to load — the first finding title appears in both list + sidebar
    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection in Login').length).toBeGreaterThanOrEqual(1)
    })
    expect(screen.getAllByText('Stored XSS in Comments').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Missing Security Headers').length).toBeGreaterThanOrEqual(1)
  })

  it('filters to critical only when critical pill is clicked', async () => {
    const user = userEvent.setup()
    renderFindings()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection in Login').length).toBeGreaterThanOrEqual(1)
    })

    // Click the "Critical" severity quick-toggle
    const critButtons = screen.getAllByRole('button', { name: /critical/i })
    const toggle = critButtons.find((btn) => btn.textContent?.includes('1'))
    expect(toggle).toBeTruthy()
    await user.click(toggle!)

    await waitFor(() => {
      expect(screen.queryByText('Stored XSS in Comments')).not.toBeInTheDocument()
    })
    expect(screen.getAllByText('SQL Injection in Login').length).toBeGreaterThanOrEqual(1)
  })
})

// ── Sort by newest ────────────────────────────────────────────────────────────

describe('Findings — sorting', () => {
  beforeEach(() => {
    vi.mocked(getFindings).mockResolvedValue({ findings: allFindings })
  })

  it('renders a sort dropdown with expected options', async () => {
    renderFindings()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection in Login').length).toBeGreaterThanOrEqual(1)
    })

    const sortSelect = screen.getByDisplayValue(/Severity/i)
    expect(sortSelect).toBeInTheDocument()

    const options = within(sortSelect as HTMLElement).getAllByRole('option')
    const labels = options.map((opt) => opt.textContent)
    expect(labels).toContain('Newest First')
    expect(labels).toContain('Oldest First')
    expect(labels).toContain('Target (A → Z)')
  })

  it('switches to flat list view when sort mode is newest', async () => {
    renderFindings()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection in Login').length).toBeGreaterThanOrEqual(1)
    })

    // Find the sort select by its label and change to newest
    const sortLabel = screen.getByText('Sort By')
    const sortSelect = sortLabel.parentElement!.querySelector('select')!
    fireEvent.change(sortSelect, { target: { value: 'newest' } })

    // When sorted by severity, grouped section headers like "Critical" show.
    // When sorted by newest, severity group headers disappear and a single
    // flat container is rendered instead.
    await waitFor(() => {
      // The severity group headers should not be rendered as section titles
      const headings = screen.getAllByText(/visible in queue/i)
      // In severity mode there are multiple (one per group), in flat mode just one
      expect(headings.length).toBe(1)
    })
  })
})

// ── Target filter ─────────────────────────────────────────────────────────────

describe('Findings — target filter', () => {
  beforeEach(() => {
    vi.mocked(getFindings).mockResolvedValue({ findings: allFindings })
  })

  it('renders target dropdown with unique targets', async () => {
    renderFindings()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection in Login').length).toBeGreaterThanOrEqual(1)
    })

    const targetSelect = screen.getByDisplayValue(/All Targets/i)
    const options = within(targetSelect as HTMLElement).getAllByRole('option')
    const labels = options.map((opt) => opt.textContent)

    expect(labels).toContain('All Targets')
    expect(labels).toContain('api.example.com')
    expect(labels).toContain('web.example.com')
  })

  it('filters findings when a specific target is selected', async () => {
    const user = userEvent.setup()
    renderFindings()

    await waitFor(() => {
      expect(screen.getAllByText('SQL Injection in Login').length).toBeGreaterThanOrEqual(1)
    })

    const targetSelect = screen.getByDisplayValue(/All Targets/i)
    await user.selectOptions(targetSelect, 'web.example.com')

    await waitFor(() => {
      expect(screen.queryByText('SQL Injection in Login')).not.toBeInTheDocument()
    })
    expect(screen.getAllByText('Stored XSS in Comments').length).toBeGreaterThanOrEqual(1)
  })
})

// ── Empty state ───────────────────────────────────────────────────────────────

describe('Findings — empty state', () => {
  it('shows empty state when no findings exist', async () => {
    vi.mocked(getFindings).mockResolvedValue({ findings: [] })
    renderFindings()

    expect(await screen.findByText(/No Findings Match/i)).toBeInTheDocument()
  })
})
