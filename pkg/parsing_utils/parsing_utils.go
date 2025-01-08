package parsing_utils

import (
	"github.com/gammazero/deque"
	goabnf "github.com/pandatix/go-abnf"
	"slices"
)

func ExtractPathValue(input []byte, path *goabnf.Path) []byte {
	return input[path.Start:path.End]
}

func _searchPath(path *goabnf.Path, names []string, maxDepth int, searchMatch bool, maxPaths int) []*goabnf.Path {
	var paths []*goabnf.Path

	currentDepth := 0
	remainingNodesAtDepth := 1
	nextDepthCount := len(path.Subpaths)

	var dq deque.Deque[*goabnf.Path]
	dq.PushBack(path)

	for dq.Len() != 0 {
		currentNode := dq.PopFront()
		nameMatches := slices.Contains(names, currentNode.MatchRule)
		if nameMatches {
			paths = append(paths, currentNode)
			if len(paths) == maxPaths {
				return paths
			}
		}

		remainingNodesAtDepth = -1

		if (maxDepth == -1 || currentDepth != maxDepth) && !(nameMatches && !searchMatch) {
			for _, subpath := range currentNode.Subpaths {
				dq.PushBack(subpath)
			}
		}

		if remainingNodesAtDepth == 0 {
			currentDepth += 1
			remainingNodesAtDepth = nextDepthCount
			nextDepthCount = 0
		}
	}

	return paths
}

func SearchPath(path *goabnf.Path, names []string, maxDepth int, searchMatch bool) []*goabnf.Path {
	return _searchPath(path, names, maxDepth, searchMatch, -1)
}

func SearchPathSingle(path *goabnf.Path, names []string, maxDepth int, searchMatch bool) *goabnf.Path {
	paths := _searchPath(path, names, maxDepth, searchMatch, 1)
	if len(paths) == 1 {
		return paths[0]
	}
	return nil
}

func SearchPathSingleName(path *goabnf.Path, name string, maxDepth int, searchMatch bool) *goabnf.Path {
	return SearchPathSingle(path, []string{name}, maxDepth, searchMatch)
}
