use crate::database::models::ObjectGroup;
use crate::server::{RuleNode, RuleType};
use petgraph::Direction::Outgoing;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use ratatui::style::{Style, Styled};
use ratatui::text::{Line, Span};
use std::collections::HashSet;
use tui_tree_widget::TreeItem;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identifier {
    pub uid: uuid::Uuid,
    pub rid: uuid::Uuid,
    pub r_type: RuleType,
}

fn build_tree_item(
    graph: &StableDiGraph<RuleNode, ()>,
    node: NodeIndex,
) -> Result<TreeItem<'static, Identifier>, std::io::Error> {
    let mut children = Vec::new();
    for child in graph.neighbors_directed(node, Outgoing) {
        children.push(build_tree_item(graph, child)?);
    }

    let n = &graph[node];
    let iden = Identifier {
        uid: uuid::Uuid::new_v4(),
        rid: n.fetch_role(),
        r_type: n.get_type(),
    };
    Ok(if children.is_empty() {
        TreeItem::new_leaf(iden, set_style(n))
    } else {
        TreeItem::new(iden, set_style(n), children)?
    })
}

fn set_style(rg: &RuleNode) -> Span<'static> {
    match rg {
        RuleNode::V0(v) => {
            if v.v_type == RuleType::Object {
                rg.label().set_style(Style::default())
            } else {
                rg.label().set_style(Style::default().bold())
            }
        }
        RuleNode::V1(v) => {
            if v.v_type == RuleType::Object {
                rg.label().set_style(Style::default())
            } else {
                rg.label().set_style(Style::default().bold())
            }
        }
    }
}

pub fn empty_group_item(
    rid: uuid::Uuid,
    name: String,
) -> Result<TreeItem<'static, Identifier>, std::io::Error> {
    let iden = Identifier {
        uid: uuid::Uuid::new_v4(),
        rid,
        r_type: RuleType::Group,
    };
    TreeItem::new(
        iden,
        Line::from(vec![
            name.set_style(Style::default().bold()),
            "(empty group)".set_style(Style::default().italic()),
        ]),
        Vec::new(),
    )
}

pub fn build_tree(
    graph: &StableDiGraph<RuleNode, ()>,
    all_groups: Vec<&ObjectGroup>,
) -> Result<Vec<TreeItem<'static, Identifier>>, std::io::Error> {
    let roots: Vec<_> = graph
        .node_indices()
        .filter(|&n| graph.neighbors_directed(n, Outgoing).next().is_some())
        .collect();

    let mut items = Vec::new();
    for root in roots {
        items.push(build_tree_item(graph, root)?);
    }

    // show empty groups
    let tree_groups: HashSet<_> = items.iter().map(|i| i.identifier().rid).collect();
    for i in all_groups
        .iter()
        .filter(|v| !tree_groups.contains(&v.id))
        .map(|v| empty_group_item(v.id, v.name.clone()))
    {
        items.push(i?);
    }

    Ok(items)
}
