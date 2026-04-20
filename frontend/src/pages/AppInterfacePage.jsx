import { useState } from 'react'

import { api } from '../api'

function AppInterfacePage({ refreshAppData, appData }) {
  const [form, setForm] = useState({ title: '', content: '' })
  const [error, setError] = useState('')

  const submit = async (event) => {
    event.preventDefault()
    setError('')
    try {
      await api.post('/api/app/data', form)
      setForm({ title: '', content: '' })
      await refreshAppData()
    } catch {
      setError('Unable to save app data')
    }
  }

  return (
    <section className="space-y-6">
      <h2 className="text-2xl font-semibold">App Interface</h2>
      <form
        className="space-y-3 rounded border border-slate-800 bg-slate-900 p-4"
        onSubmit={submit}
      >
        <input
          className="w-full rounded bg-slate-800 p-2"
          placeholder="Title"
          value={form.title}
          onChange={(event) =>
            setForm((prev) => ({ ...prev, title: event.target.value }))
          }
          required
        />
        <textarea
          className="min-h-32 w-full rounded bg-slate-800 p-2"
          placeholder="Content"
          value={form.content}
          onChange={(event) =>
            setForm((prev) => ({ ...prev, content: event.target.value }))
          }
          required
        />
        {error ? <p className="text-sm text-rose-400">{error}</p> : null}
        <button className="rounded bg-blue-600 px-4 py-2">Store data</button>
      </form>

      <div className="rounded border border-slate-800 bg-slate-900 p-4">
        <h3 className="mb-2 font-semibold">Stored Data</h3>
        <ul className="space-y-2 text-sm">
          {appData.map((item) => (
            <li key={item.id} className="rounded bg-slate-800 p-2">
              <p className="font-medium">{item.title}</p>
              <p className="text-slate-300">{item.content}</p>
            </li>
          ))}
          {!appData.length ? (
            <li className="text-slate-400">No data yet.</li>
          ) : null}
        </ul>
      </div>
    </section>
  )
}

export default AppInterfacePage
