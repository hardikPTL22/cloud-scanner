import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/scan')({
  component: RouteComponent,
})

function RouteComponent() {
  return <div>Hello "/scan"!</div>
}
