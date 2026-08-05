Strong +1 on a first-class compaction lifecycle signal. One refinement worth considering: the **covered set** matters as much as the through-pointer.

`compactedThroughMessageId` tells a consumer where the boundary sits, but not which prior messages are represented in the summary. Those are different questions once anything downstream needs to reason about where a later assertion came from.

The lossiness is measured, not hypothetical. A benchmark of 36,611 production messages found three widely-used summarization approaches scoring 2.19–2.45 out of 5.0 on artifact tracking — summaries reliably drop which specific artifacts a segment touched. In our own work on dependency tracing across session boundaries, recall of true upstream dependencies fell from 100% to 3% as the fraction of dependencies carried without a re-read went from 0 to 1. A through-pointer alone doesn't recover that; an explicit covered set does.

So concretely, alongside `compactedThroughMessageId`, something like a `covers` array of the message ids represented, plus a stable `boundaryId` for the event itself so consumers can reference it after the fact.

Deliberately not proposing any hashing or attestation here — that belongs in whatever layer cares about it, not the protocol. The primitive I'd want standardized is just: this compaction happened, here is its id, here is what it covers.

Happy to share an implementation if it's useful as a reference.
