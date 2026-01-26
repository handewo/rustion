use crate::server::RuleGroup;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::Direction::{Incoming, Outgoing};
use ratatui::style::{Style, Styled};
use ratatui::text::Span;
use tui_tree_widget::TreeItem;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Identifier {
    pub uid: uuid::Uuid,
    pub role: String,
}

fn build_tree_item(
    graph: &StableDiGraph<RuleGroup, ()>,
    node: NodeIndex,
) -> Result<TreeItem<'static, Identifier>, std::io::Error> {
    let mut children = Vec::new();
    for child in graph.neighbors_directed(node, Outgoing) {
        children.push(build_tree_item(graph, child)?);
    }

    let n = &graph[node];
    let iden = Identifier {
        uid: uuid::Uuid::new_v4(),
        role: n.fetch_role().to_string(),
    };
    Ok(if children.is_empty() {
        TreeItem::new_leaf(iden, set_style(n))
    } else {
        TreeItem::new(iden, set_style(n), children)?
    })
}

fn set_style(rg: &RuleGroup) -> Span<'static> {
    if let RuleGroup::V0(ref v) = rg {
        if v.v0_label.is_some() {
            return rg.label().set_style(Style::default());
        }
    }
    rg.label().set_style(Style::default().bold())
}

pub fn build_tree(
    graph: &StableDiGraph<RuleGroup, ()>,
) -> Result<Vec<TreeItem<'static, Identifier>>, std::io::Error> {
    let roots: Vec<_> = graph
        .node_indices()
        .filter(|&n| graph.neighbors_directed(n, Incoming).next().is_none())
        .collect();

    let mut items = Vec::new();
    for root in roots {
        items.push(build_tree_item(graph, root)?);
    }

    Ok(items)
}
